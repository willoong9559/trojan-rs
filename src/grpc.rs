use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use h2::{server, SendStream, RecvStream, Reason};
use http::{Response, StatusCode};
use anyhow::Result;
use futures_util::Future;
use tokio::sync::Semaphore;

const READ_BUFFER_SIZE: usize = 256 * 1024;
const WRITE_BUFFER_SIZE: usize = 128 * 1024;
const MAX_CONCURRENT_STREAMS: usize = 100;

/// gRPC HTTP/2 连接管理器
/// 
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    stream_semaphore: Arc<Semaphore>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
        let h2_conn = server::handshake(stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;
        
        // 注意：h2 库的并发流限制通过信号量在应用层控制
        // HTTP/2 协议本身也有流控机制
        
        Ok(Self { 
            h2_conn,
            stream_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
        })
    }

    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let stream_semaphore = self.stream_semaphore;
        
        loop {
            match h2_conn.accept().await {
                Some(Ok((request, mut respond))) => {
                    if request.method() != http::Method::POST {
                        let response = Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    let path = request.uri().path();
                    if !path.ends_with("/Tun") {
                        let response = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();

                    let send_stream = match respond.send_response(response, false) {
                        Ok(stream) => stream,
                        Err(_) => continue,
                    };

                    let recv_stream = request.into_body();

                    let permit = match stream_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            // 流数量已达上限，拒绝请求
                            let response = Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .header("grpc-status", "8")  // RESOURCE_EXHAUSTED
                                .body(())
                                .unwrap();
                            let _ = respond.send_response(response, true);
                            continue;
                        }
                    };

                    let transport = GrpcH2cTransport {
                        recv_stream,
                        send_stream,
                        read_pending: BytesMut::with_capacity(READ_BUFFER_SIZE),
                        read_buf: Vec::new(),
                        read_pos: 0,
                        write_buf: BytesMut::with_capacity(WRITE_BUFFER_SIZE),
                        closed: false,
                    };

                    let handler_clone = Arc::clone(&handler);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = handler_clone(transport).await;
                    });
                }
                Some(Err(e)) => {
                    return Err(anyhow::anyhow!("gRPC connection error: {}", e));
                }
                None => {
                    break;
                }
            }
        }
        Ok(())
    }
}

/// gRPC 传输层（兼容 v2ray）
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    recv_stream: RecvStream,
    send_stream: SendStream<Bytes>,
    read_pending: BytesMut,
    read_buf: Vec<u8>,
    read_pos: usize,
    write_buf: BytesMut,
    closed: bool,
}

/// 解析 gRPC 消息帧（兼容 v2ray 格式）
/// 
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
fn parse_grpc_message(buf: &BytesMut) -> io::Result<Option<(usize, Vec<u8>)>> {
    if buf.len() < 6 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported"
        ));
    }

    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if buf.len() < 5 + grpc_frame_len {
        return Ok(None);
    }

    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected protobuf tag: 0x{:02X}, expected 0x0A", buf[5])
        ));
    }

    let (payload_len_u64, varint_bytes) = decode_varint(&buf[6..])?;
    let payload_len = payload_len_u64 as usize;
    let data_start = 6 + varint_bytes;
    let data_end = data_start + payload_len;

    if data_end > 5 + grpc_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload length {} exceeds gRPC frame length {}", payload_len, grpc_frame_len)
        ));
    }

    let payload = buf[data_start..data_end].to_vec();
    let consumed = 5 + grpc_frame_len;
    
    Ok(Some((consumed, payload)))
}

/// 编码 gRPC 消息帧
fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    let mut proto_header = BytesMut::with_capacity(10);
    proto_header.put_u8(0x0A);
    encode_varint(payload.len() as u64, &mut proto_header);

    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;
    let mut buf = BytesMut::with_capacity(5 + proto_header.len() + payload.len());
    buf.put_u8(0x00);
    buf.put_u32(grpc_payload_len);
    buf.extend_from_slice(&proto_header);
    buf.extend_from_slice(payload);

    buf
}

/// 解码 varint
fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint too long"));
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete varint"))
}

/// 编码 varint
fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

fn is_normal_stream_close(error: &h2::Error) -> bool {
    // 根据 HTTP/2 规范，NO_ERROR (0x0) 和 CANCEL (0x8) 表示正常的流关闭
    if let Some(reason) = error.reason() {
        matches!(
            reason,
            Reason::NO_ERROR
                | Reason::CANCEL
        )
    } else {
        false
    }
}

impl AsyncRead for GrpcH2cTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

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

        loop {
            match parse_grpc_message(&self.read_pending) {
                Ok(Some((consumed, payload))) => {
                    let _ = self.recv_stream.flow_control().release_capacity(consumed);
                    self.read_pending.advance(consumed);
                    
                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);
                    
                    if to_copy < payload.len() {
                        self.read_buf = payload;
                        self.read_pos = to_copy;
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }

            let poll_result = {
                let data_future = self.recv_stream.data();
                Pin::new(&mut Box::pin(data_future)).poll(cx)
            };
            
            match poll_result {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.read_pending.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    self.closed = true;
                    if is_normal_stream_close(&e) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("gRPC recv error: {}", e),
                    )));
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for GrpcH2cTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed"
            )));
        }

        // 尝试发送待发送的数据
        if !self.write_buf.is_empty() {
            match self.try_send_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.write_buf.extend_from_slice(buf);
        
        // 尝试立即发送
        match self.try_send_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.write_buf.is_empty() {
            self.try_send_pending(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                match self.send_stream.send_trailers(trailers) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("gRPC send trailers error: {}", e),
                    ))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl GrpcH2cTransport {
    fn try_send_pending(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let frame = encode_grpc_message(&self.write_buf);
        let frame_len = frame.len();
        let capacity = self.send_stream.capacity();
        
        if capacity < frame_len {
            self.send_stream.reserve_capacity(frame_len);
            return Poll::Pending;
        }
        
        let frame_bytes = frame.freeze();
        match self.send_stream.send_data(frame_bytes, false) {
            Ok(()) => {
                self.write_buf.clear();
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("gRPC send error: {}", e),
            ))),
        }
    }
}
