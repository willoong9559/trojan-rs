use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use bytes::{BytesMut, Buf, BufMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use h2::client;
use http;

/// 在明文 TCP 上用 h2 prior-knowledge 建立 gRPC POST 流，
/// 并把它封装成实现 AsyncRead + AsyncWrite 的传输层。
pub struct GrpcH2cTransport {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl GrpcH2cTransport {
    /// 创建并立即发起 POST /{service}/Tun
    /// - `tcp`: 已连接的 TcpStream（明文）
    /// - `service`: service 名，如 "GunService"
    pub async fn new<S>(tcp: S, service: &str) -> io::Result<Self> 
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // h2 prior-knowledge handshake over the plain TCP stream
        // client::handshake 可以在任意 AsyncRead+AsyncWrite 上工作（会发送 client preface）
        let (mut h2, connection) = client::handshake(tcp).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;

        // spawn connection drive task
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("h2 connection error: {}", e);
            }
        });

        // build request
        let path = format!("/{}/Tun", service);
        let req = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/grpc")
            .header("user-agent", "grpc-rust/0.1")
            .body(())
            .unwrap();

        // send request without ending body (we will stream body)
        let (response_fut, mut send_stream) = h2.send_request(req, false)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("send_request: {}", e)))?;

        // wait response headers (server may send headers)
        let response = response_fut.await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("response error: {}", e)))?;
        let mut recv_stream = response.into_body();

        // channels between background tasks and AsyncRead/Write impl
        let (read_tx, read_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // reading task: receive DATA frames from server, assemble and parse gRPC/protobuf payloads
        tokio::spawn(async move {
            // We maintain a growing buffer because a single incoming h2 chunk may not align with gRPC frame boundaries.
            let mut pending = BytesMut::new();

            while let Some(res) = recv_stream.data().await {
                match res {
                    Ok(chunk) => {
                        pending.extend_from_slice(&chunk);
                        // try to parse as many complete frames as possible
                        while let Some((consumed, payload)) = try_extract_grpc_payload(&pending) {
                            let _ = read_tx.send(payload);
                            pending.advance(consumed);
                        }
                    }
                    Err(e) => {
                        eprintln!("recv_stream.data error: {}", e);
                        break;
                    }
                }
            }
            // close read_tx by dropping
        });

        // writing task: receive raw payloads from upper layer, pack then send as DATA frames
        tokio::spawn(async move {
            while let Some(payload) = write_rx.recv().await {
                let packed = pack_message(&payload);
                if send_stream.send_data(packed.freeze(), false).is_err() {
                    break;
                }
            }
            // finish stream
            let _ = send_stream.send_trailers(http::HeaderMap::new());
        });

        Ok(Self {
            read_rx,
            write_tx,
            read_buf: Vec::new(),
            read_pos: 0,
        })
    }
}

// Helper: try to extract one whole gRPC message payload from buffer
// Returns: Some((consumed_bytes, payload_bytes)) if a full message parsed, else None.
fn try_extract_grpc_payload(buf: &BytesMut) -> Option<(usize, Vec<u8>)> {
    // Minimal bytes check:
    // Go code discarded 6 bytes (0x00 + 4-byte len + 0x0A) then read uvarint length then payload.
    // But in practice, the buffer may contain arbitrary alignment. We try to parse conservative:
    if buf.len() < 6 {
        return None;
    }

    // Expect first byte is 0x00 (grpc compression flag) — if not, it's possible server sends other frames; bail out
    if buf[0] != 0x00 {
        // Can't parse — to be robust, search for 0x00? For now return None and wait for more data
        return None;
    }

    // Read 4-byte big-endian grpc length (length of following protobuf header + message)
    let grpc_len = {
        let b1 = buf[1] as u32;
        let b2 = buf[2] as u32;
        let b3 = buf[3] as u32;
        let b4 = buf[4] as u32;
        ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4) as usize
    };

    // total bytes needed for the entire gRPC payload (excluding initial 5 bytes flag+len)
    if buf.len() < 5 + grpc_len {
        return None;
    }

    // Now inside the grpc payload, Go expected first byte 0x0A (protobuf field) then uvarint for message len.
    // In Go they did: Discard(6) (5 header + first 0x0A), then binary.ReadUvarint to get protobufPayloadLen
    if buf[5] != 0x0A {
        // Unexpected layout; give up for now
        return None;
    }

    // parse uvarint starting at buf[6..]
    let mut idx = 6;
    let mut msg_len: usize = 0;
    let mut shift = 0;
    while idx < 5 + grpc_len {
        let b = buf[idx];
        idx += 1;
        msg_len |= ((b & 0x7F) as usize) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }

    // Now idx is the start of the message payload
    let remain = 5 + grpc_len - idx;
    if remain < msg_len {
        // not yet full
        return None;
    }

    let payload_start = idx;
    let payload_end = idx + msg_len;
    let payload = buf[payload_start..payload_end].to_vec();
    let consumed = 5 + grpc_len; // we consumed full grpc payload block
    Some((consumed, payload))
}

// Pack a message same as Go Write:
// grpc header: 0x00 + 4-byte big-endian length (protobuf_header + payload)
// protobuf header: 0x0A + uvarint(payload_len)
// payload: bytes
fn pack_message(payload: &[u8]) -> BytesMut {
    let mut proto_hdr = BytesMut::with_capacity(10);
    proto_hdr.put_u8(0x0A);
    let mut x = payload.len() as u64;
    loop {
        let mut byte = (x & 0x7F) as u8;
        x >>= 7;
        if x != 0 {
            byte |= 0x80;
        }
        proto_hdr.put_u8(byte);
        if x == 0 {
            break;
        }
    }

    let grpc_payload_len = (proto_hdr.len() + payload.len()) as u32;
    let mut buf = BytesMut::with_capacity(5 + grpc_payload_len as usize);
    buf.put_u8(0x00);
    buf.put_u32(grpc_payload_len);
    buf.extend_from_slice(&proto_hdr);
    buf.extend_from_slice(payload);
    buf
}

// ------ AsyncRead + AsyncWrite impl: behave like a normal duplex stream ------

impl AsyncRead for GrpcH2cTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // consume internal buffer first
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.read_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf = data;
                    self.read_pos = to_copy;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // channel closed -> EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcH2cTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "write channel closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // we don't provide explicit flush semantics here
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // drop sender will cause the writer task to finish and send trailers
        Poll::Ready(Ok(()))
    }
}
