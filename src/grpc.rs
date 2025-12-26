use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use h2::{server, RecvStream, SendStream};
use http::{Response, StatusCode};
use anyhow::Result;

const MAX_PENDING_SIZE: usize = 256 * 1024;

/// gRPC HTTP/2 连接管理器
/// 
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
/// 兼容 v2ray 的 gRPC 传输层
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// 从 TCP 流创建 HTTP/2 连接管理器
    pub async fn new(stream: S) -> io::Result<Self> {
        // HTTP/2 服务端握手
        let h2_conn = server::handshake(stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;

        Ok(Self { h2_conn })
    }

    /// 运行连接管理器，接受所有流并调用回调函数处理每个流
    /// 
    /// 这个函数会持续运行直到连接关闭
    /// HTTP/2 连接驱动会在后台任务中运行
    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        
        let mut h2_conn = self.h2_conn;
        
        loop {
            match h2_conn.accept().await {
                Some(Ok((request, mut respond))) => {
                    // 验证请求方法
                    if request.method() != http::Method::POST {
                        let response = Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    // 验证路径格式：应该是 /{path}/Tun
                    let path = request.uri().path();
                    if !path.ends_with("/Tun") {
                        let response = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    // 发送 200 OK 响应（兼容 v2ray）
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

                    // 为每个流创建传输层（零拷贝）
                    let transport = GrpcH2cTransport {
                        recv_stream: Some(recv_stream),
                        send_stream: Some(send_stream),
                        read_pending: BytesMut::new(),
                        read_buf: Bytes::new(),
                        read_pos: 0,
                        write_pending: None,
                        closed: false,
                    };

                    let transport_clone = transport;
                    let handler_clone = Arc::clone(&handler);
                    tokio::spawn(async move {
                        if let Err(e) = handler_clone(transport_clone).await {
                            eprintln!("[gRPC] Stream handler error: {}", e);
                        }
                    });
                }
                Some(Err(e)) => {
                    // 检查是否是致命错误
                    let error_str = e.to_string();
                    if error_str.contains("connection reset") || error_str.contains("broken pipe") {
                        eprintln!("[gRPC] Connection error (likely closed): {}", e);
                        break;
                    } else {
                        eprintln!("[gRPC] Error accepting stream: {}", e);
                    }
                }
                None => {
                    // 连接关闭（正常关闭）
                    eprintln!("[gRPC] Connection closed normally");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// gRPC 传输层
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
/// 每个实例对应一个 HTTP/2 流，支持多路复用
pub struct GrpcH2cTransport {
    recv_stream: Option<RecvStream>,
    send_stream: Option<SendStream<Bytes>>,
    read_pending: BytesMut,  // 从 gRPC 流接收的原始数据
    read_buf: Bytes,  // 解析后的 payload 数据
    read_pos: usize,
    write_pending: Option<Bytes>,  // 待发送的数据（使用 Bytes 引用计数，避免复制）
    closed: bool,
}

impl GrpcH2cTransport {
    // GrpcH2cTransport 现在通过 GrpcH2cConnection::accept_next_stream() 创建
    // 保留这个空实现块以便将来扩展
}

// ==================== 帧编解码（v2ray gRPC 格式）====================

/// 解析 gRPC 消息帧（兼容 v2ray 格式）
/// 
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
/// - gRPC 头部：1字节压缩标志(0x00) + 4字节长度(大端)
/// - protobuf 头部：1字节 tag(0x0A) + varint(数据长度)
/// - 数据：实际 payload
fn parse_grpc_message(buf: &mut BytesMut) -> io::Result<Option<(usize, Bytes)>> {
    // 至少需要 6 字节才能开始解析（5字节gRPC头部 + 1字节protobuf tag）
    if buf.len() < 6 {
        return Ok(None);
    }

    // 检查压缩标志（必须是 0x00，不支持压缩）
    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported"
        ));
    }

    // 读取 gRPC 帧长度（4字节，大端）
    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    // 检查是否有足够的数据
    if buf.len() < 5 + grpc_frame_len {
        return Ok(None);
    }

    // 检查 protobuf tag（必须是 0x0A，表示 length-delimited field）
    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected protobuf tag: 0x{:02X}, expected 0x0A", buf[5])
        ));
    }

    // 解析 varint 获取 payload 长度
    let (payload_len_u64, varint_bytes) = decode_varint(&buf[6..])?;
    let payload_len = payload_len_u64 as usize;

    // 计算数据起始和结束位置
    let data_start = 6 + varint_bytes;
    let data_end = data_start + payload_len;

    // 验证数据长度不超过 gRPC 帧
    if data_end > 5 + grpc_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload length {} exceeds gRPC frame length {}", payload_len, grpc_frame_len)
        ));
    }

    // 提取 payload（使用 Bytes 引用计数共享）
    // 直接从 BytesMut 创建 Bytes
    // 使用 split_off 和 split_to 来避免复制
    let mut temp = buf.split_off(data_start);
    let payload = temp.split_to(data_end - data_start).freeze();
    let consumed = 5 + grpc_frame_len;
    
    Ok(Some((consumed, payload)))
}

/// 编码 gRPC 消息帧（兼容 v2ray 格式）
/// 
/// 格式与解析格式相同
fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    // 构建 protobuf 头部：0x0A + varint(长度)
    let mut proto_header = BytesMut::with_capacity(10);
    proto_header.put_u8(0x0A);
    encode_varint(payload.len() as u64, &mut proto_header);

    // gRPC 帧总长度（protobuf头部 + payload）
    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;

    // 完整的 gRPC 帧
    let mut buf = BytesMut::with_capacity(5 + proto_header.len() + payload.len());
    buf.put_u8(0x00);  // 压缩标志：0x00 表示未压缩
    buf.put_u32(grpc_payload_len);  // gRPC 帧长度（大端）
    buf.extend_from_slice(&proto_header);  // protobuf 头部
    buf.extend_from_slice(payload);  // 实际数据

    buf
}

/// 解码 varint（兼容 prost 格式，使用 u64）
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

/// 编码 varint（兼容 prost 格式，使用 u64）
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

        // 如果缓冲区还有数据，先消费缓冲区
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buf.len() {
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // 从 gRPC 流直接读取并解析（零拷贝，不使用通道）
        // 循环解析完整的 gRPC 消息
        loop {
            // 先尝试从 pending 缓冲区解析
            let parse_result = parse_grpc_message(&mut self.read_pending);
            match parse_result {
                Ok(Some((consumed, payload))) => {
                    self.read_pending.advance(consumed);
                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);

                    if to_copy < payload.len() {
                        self.read_buf = payload;
                        self.read_pos = to_copy;
                    }

                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {
                    // 数据不足，需要读取更多
                }
                Err(e) => {
                    eprintln!("[gRPC] Parse error: {}", e);
                    // 跳过错误字节，尝试恢复
                    if !self.read_pending.is_empty() {
                        self.read_pending.advance(1);
                        continue;
                    } else {
                        return Poll::Ready(Err(e));
                    }
                }
            }

            // 从 gRPC 流读取数据
            // 使用独立作用域限制 recv_stream 的借用
            let (chunk_result, mut flow_control) = {
                let recv_stream = match &mut self.recv_stream {
                    Some(stream) => stream,
                    None => {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                };
                let flow_control = recv_stream.flow_control().clone();
                let data_future = recv_stream.data();
                let result = Box::pin(data_future).as_mut().poll(cx);
                (result, flow_control)
            };
            
            // 处理读取结果
            match chunk_result {
                Poll::Ready(Some(Ok(chunk))) => {
                    let chunk_len = chunk.len();
                    // 限制 pending 缓冲区大小，防止内存溢出
                    let pending_len = self.read_pending.len();
                    if pending_len + chunk_len > MAX_PENDING_SIZE {
                        eprintln!("[gRPC] Pending buffer too large ({}), dropping connection", pending_len);
                        self.closed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "gRPC pending buffer too large"
                        )));
                    }
                    
                    // 优化：如果 read_pending 为空，直接使用 chunk 转换为 BytesMut
                    // 否则需要复制到 read_pending（这是必要的，因为需要合并数据）
                    if self.read_pending.is_empty() {
                        // 如果 pending 为空，直接使用 chunk 的底层数据（避免一次复制）
                        self.read_pending = BytesMut::from(&chunk[..]);
                    } else {
                        // 需要合并数据，必须复制
                        self.read_pending.extend_from_slice(&chunk);
                    }
                    
                    // 释放流控容量（在借用 self 之后）
                    flow_control.release_capacity(chunk_len)
                        .unwrap_or_else(|e| {
                            eprintln!("[gRPC] Failed to release capacity: {}", e);
                        });
                    
                    // 继续循环解析
                }
                Poll::Ready(Some(Err(e))) => {
                    // 忽略正常的流结束信号
                    if !e.to_string().contains("not a result of an error") {
                        eprintln!("[gRPC] Recv error: {}", e);
                    }
                    self.closed = true;
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(None) => {
                    self.closed = true;
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Pending => {
                    // 数据不足，等待更多数据
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

        // 如果有待发送的数据，先尝试发送
        if let Some(pending) = self.write_pending.take() {
            let send_stream = match &mut self.send_stream {
                Some(stream) => stream,
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "send stream closed"
                    )));
                }
            };
            // pending 是 Bytes，直接使用引用，避免复制
            let frame = encode_grpc_message(&pending);
            match send_stream.send_data(frame.freeze(), false) {
                Ok(()) => {
                    // 继续处理新数据
                }
                Err(e) => {
                    // 发送失败，保存数据等待重试（Bytes 引用计数，不复制）
                    self.write_pending = Some(pending);
                    // 检查是否是流控问题
                    if e.is_io() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )));
                }
            }
        }

        // 直接编码并发送新数据
        let send_stream = match &mut self.send_stream {
            Some(stream) => stream,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "send stream closed"
                )));
            }
        };
        
        // 使用 Bytes::copy_from_slice 创建 Bytes（最小化复制）
        let frame = encode_grpc_message(buf);
        match send_stream.send_data(frame.freeze(), false) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => {
                // 发送失败，保存数据等待重试（使用 Bytes 引用计数）
                self.write_pending = Some(Bytes::copy_from_slice(buf));
                // 检查是否是流控问题
                if e.is_io() {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 发送 gRPC 状态 trailers
        if let Some(send_stream) = &mut self.send_stream {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            let _ = send_stream.send_trailers(trailers);
        }
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

