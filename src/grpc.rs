use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use bytes::{BytesMut, Buf, BufMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use h2::{server};
use http::{Response, StatusCode};

/// Gun/gRPC 传输层
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    closed: bool,
}

impl GrpcH2cTransport {
    /// 服务端模式：从已有 TCP 流升级为 gRPC 传输
    /// 
    /// # 参数
    /// - `stream`: 底层 TCP 连接
    /// - `service_name`: 期望的服务名称，用于验证请求路径
    /// 
    /// # 工作流程
    /// 1. 执行 HTTP/2 服务端握手
    /// 2. 接受第一个请求（应该是 POST /{service_name}/Tun）
    /// 3. 验证请求路径和 Content-Type
    /// 4. 返回 GrpcH2cTransport 实例用于数据传输
    pub async fn new<S>(
        stream: S,
        service_name: &str,
    ) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // HTTP/2 服务端握手
        let mut h2_conn = server::handshake(stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;

        // 接受第一个请求
        let (request, mut respond) = h2_conn.accept().await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no request received"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("accept error: {}", e)))?;

        // 验证请求
        let expected_path = format!("/{}/Tun", service_name);
        if request.uri().path() != expected_path {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap();
            respond.send_response(response, true)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid path: expected {}, got {}", expected_path, request.uri().path())
            ));
        }

        if request.method() != http::Method::POST {
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(())
                .unwrap();
            respond.send_response(response, true)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid method: expected POST"
            ));
        }

        // 可选：验证 Content-Type
        if let Some(ct) = request.headers().get("content-type") {
            if ct != "application/grpc" {
                let response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(())
                    .unwrap();
                respond.send_response(response, true)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid content-type"
                ));
            }
        }

        // 发送 200 OK 响应
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();

        let mut send_stream = respond.send_response(response, false)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut recv_stream = request.into_body();

        // 创建数据通道
        // 创建数据通道
        let (read_tx, read_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // 读取任务
        tokio::spawn(async move {
            let mut pending = BytesMut::new();
            loop {
                match recv_stream.data().await {
                    Some(Ok(chunk)) => {
                        pending.extend_from_slice(&chunk);
                        loop {
                            match parse_gun_message(&pending) {
                                Ok(Some((consumed, payload))) => {
                                    if read_tx.send(payload).is_err() {
                                        return;
                                    }
                                    pending.advance(consumed);
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    eprintln!("[Gun Server] parse error: {}", e);
                                    if !pending.is_empty() {
                                        pending.advance(1);
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("[Gun Server] recv error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
        });

        // 写入任务
        tokio::spawn(async move {
            while let Some(payload) = write_rx.recv().await {
                let frame = encode_gun_message(&payload);
                if send_stream.send_data(frame.freeze(), false).is_err() {
                    break;
                }
            }
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            let _ = send_stream.send_trailers(trailers);
        });

        // 启动 HTTP/2 连接驱动任务
        tokio::spawn(async move {
            while h2_conn.accept().await.is_some() {
                // 忽略后续请求，Gun 协议只使用第一个流
            }
        });

        Ok(Self {
            read_rx,
            write_tx,
            read_buf: Vec::new(),
            read_pos: 0,
            closed: false,
        })
    }
}

// ==================== 帧编解码 ====================

fn parse_gun_message(buf: &BytesMut) -> io::Result<Option<(usize, Vec<u8>)>> {
    if buf.len() < 6 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported"
        ));
    }

    let grpc_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if buf.len() < 5 + grpc_len {
        return Ok(None);
    }

    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected protobuf tag: 0x{:02X}", buf[5])
        ));
    }

    let (payload_len, varint_bytes) = decode_varint(&buf[6..])?;

    let data_start = 6 + varint_bytes;
    let data_end = data_start + payload_len;

    if data_end > 5 + grpc_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload length exceeds gRPC frame"
        ));
    }

    let payload = buf[data_start..data_end].to_vec();
    Ok(Some((5 + grpc_len, payload)))
}

fn encode_gun_message(payload: &[u8]) -> BytesMut {
    let mut proto_header = Vec::with_capacity(10);
    proto_header.push(0x0A);
    encode_varint(payload.len(), &mut proto_header);

    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;

    let mut buf = BytesMut::with_capacity(5 + grpc_payload_len as usize);
    buf.put_u8(0x00);
    buf.put_u32(grpc_payload_len);
    buf.extend_from_slice(&proto_header);
    buf.extend_from_slice(payload);

    buf
}

fn decode_varint(data: &[u8]) -> io::Result<(usize, usize)> {
    let mut result = 0usize;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint too long"));
        }

        result |= ((byte & 0x7F) as usize) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete varint"))
}

fn encode_varint(mut value: usize, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

// ==================== AsyncRead + AsyncWrite 实现 ====================

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
                self.closed = true;
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
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed"
            )));
        }

        match self.write_tx.send(buf.to_vec()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write channel closed"
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}
