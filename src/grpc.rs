use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use h2::{server, SendStream, RecvStream};
use http::{Response, StatusCode};
use anyhow::Result;

// gRPC pending 缓冲区最大大小（约 1MB）
const MAX_PENDING_SIZE: usize = 1024 * 1024;

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
        
        // h2 的 Connection 需要被驱动，但 accept() 方法内部会处理
        // 为了确保连接被正确驱动，我们使用一个包装来同时处理连接驱动和接受流
        // 使用 poll_fn 来手动轮询连接，同时接受流
        
        let mut h2_conn = self.h2_conn;
        
        loop {
            // 使用 futures_util::future::poll_fn 来手动轮询连接
            // 但 accept() 本身是异步的，我们需要在循环中调用它
            // 实际上，根据 h2 的实现，accept() 会处理连接驱动
            
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

                    // 验证 Content-Type（可选，兼容性更好）
                    // v2ray 客户端会发送 "application/grpc"

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

                    // 为每个流创建传输层并启动处理任务
                    let transport = GrpcH2cTransport {
                        recv_stream,
                        send_stream,
                        read_pending: BytesMut::new(),
                        read_buf: Vec::new(),
                        read_pos: 0,
                        write_buf: BytesMut::new(),
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

/// gRPC 传输层（兼容 v2ray）
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
/// 每个实例对应一个 HTTP/2 流，支持多路复用
/// 使用零成本抽象，直接操作 HTTP/2 流，无需通道复制
pub struct GrpcH2cTransport {
    recv_stream: RecvStream,
    send_stream: SendStream<Bytes>,
    read_pending: BytesMut,  // 从 HTTP/2 流接收的原始数据
    read_buf: Vec<u8>,        // 已解析的 gRPC payload 缓冲区
    read_pos: usize,          // read_buf 的读取位置
    write_buf: BytesMut,      // 待写入的 gRPC 帧缓冲区
    closed: bool,
}

// 帧编解码

/// 解析 gRPC 消息帧（兼容 v2ray 格式）
/// 
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
/// - gRPC 头部：1字节压缩标志(0x00) + 4字节长度(大端)
/// - protobuf 头部：1字节 tag(0x0A) + varint(数据长度)
/// - 数据：实际 payload
fn parse_grpc_message(buf: &BytesMut) -> io::Result<Option<(usize, Vec<u8>)>> {
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

    // 提取 payload
    let payload = buf[data_start..data_end].to_vec();
    let consumed = 5 + grpc_frame_len;
    
    Ok(Some((consumed, payload)))
}

/// 编码 gRPC 消息帧
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

// AsyncRead + AsyncWrite 实现

impl GrpcH2cTransport {
    /// 释放流控容量，统一错误处理
    fn release_flow_control_capacity(recv_stream: &mut RecvStream, capacity: usize, context: &str) {
        if capacity > 0 {
            let flow_control = recv_stream.flow_control();
            if let Err(e) = flow_control.release_capacity(capacity) {
                eprintln!("[gRPC] Failed to release capacity {}: {}", context, e);
            }
        }
    }

    /// 检查是否是流控错误
    fn is_flow_control_error(error: &h2::Error) -> bool {
        let error_str = error.to_string();
        error_str.contains("user error") || error_str.contains("stream error")
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

        // 如果已解析的缓冲区还有数据，先消费
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

        // 从 HTTP/2 流读取数据并解析 gRPC 帧
        loop {
            // 尝试从 pending 缓冲区解析完整的 gRPC 消息
            match parse_grpc_message(&self.read_pending) {
                Ok(Some((consumed, payload))) => {
                    // 释放流控容量
                    Self::release_flow_control_capacity(&mut self.recv_stream, consumed, "on message parse");
                    
                    self.read_pending.advance(consumed);
                    
                    // 将解析出的 payload 放入 read_buf
                    let to_copy = payload.len().min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);
                    
                    if to_copy < payload.len() {
                        self.read_buf = payload;
                        self.read_pos = to_copy;
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {
                    // 数据不足，需要从流中读取更多数据
                }
                Err(e) => {
                    eprintln!("[gRPC] Parse error: {}", e);
                    // 如果 pending 缓冲区太大，释放一些容量并清理
                    if self.read_pending.len() > MAX_PENDING_SIZE / 2 {
                        // 释放已读取的数据的流控容量（即使无法解析）
                        let to_release = self.read_pending.len() / 2;
                        Self::release_flow_control_capacity(&mut self.recv_stream, to_release, "on parse error (large buffer)");
                        self.read_pending.advance(to_release);
                        // 继续尝试解析剩余数据
                        continue;
                    }
                    // 跳过错误字节，尝试恢复
                    if !self.read_pending.is_empty() {
                        // 释放跳过的字节的流控容量
                        Self::release_flow_control_capacity(&mut self.recv_stream, 1, "on parse error (skip byte)");
                        self.read_pending.advance(1);
                        continue;
                    } else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("gRPC parse error: {}", e),
                        )));
                    }
                }
            }

            // 从 HTTP/2 流读取数据
            // 直接创建并轮询 future，不存储它以避免生命周期问题
            let poll_result = {
                let data_future = self.recv_stream.data();
                Pin::new(&mut Box::pin(data_future)).poll(cx)
            };
            
            match poll_result {
                Poll::Ready(Some(Ok(chunk))) => {
                    let chunk_len = chunk.len();
                    // 限制 pending 缓冲区大小，防止内存溢出
                    if self.read_pending.len() + chunk_len > MAX_PENDING_SIZE {
                        eprintln!("[gRPC] Pending buffer too large ({}), releasing capacity and dropping connection", self.read_pending.len());
                        // 释放已读取的数据的流控容量
                        let total_len = self.read_pending.len() + chunk_len;
                        Self::release_flow_control_capacity(&mut self.recv_stream, total_len, "on buffer overflow");
                        self.closed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::OutOfMemory,
                            "gRPC pending buffer too large",
                        )));
                    }
                    
                    self.read_pending.extend_from_slice(&chunk);
                    // 继续循环，尝试解析
                }
                Poll::Ready(Some(Err(e))) => {
                    // 释放 pending 缓冲区中剩余数据的流控容量
                    let pending_len = self.read_pending.len();
                    Self::release_flow_control_capacity(&mut self.recv_stream, pending_len, "on recv error");
                    // 忽略正常的流结束信号
                    if !e.to_string().contains("not a result of an error") {
                        eprintln!("[gRPC] Recv error: {}", e);
                    }
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    // 释放 pending 缓冲区中剩余数据的流控容量
                    let pending_len = self.read_pending.len();
                    Self::release_flow_control_capacity(&mut self.recv_stream, pending_len, "on stream end");
                    // 流结束
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

        // 将数据添加到写入缓冲区
        self.write_buf.extend_from_slice(buf);
        
        // 限制写入缓冲区大小，防止内存溢出
        if self.write_buf.len() > MAX_PENDING_SIZE {
            eprintln!("[gRPC] Write buffer too large ({}), dropping connection", self.write_buf.len());
            self.closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "gRPC write buffer too large",
            )));
        }
        
        // 尝试发送缓冲区中的数据
        if !self.write_buf.is_empty() {
            let frame = encode_grpc_message(&self.write_buf);
            let frame_bytes = frame.freeze();
            
            match self.send_stream.send_data(frame_bytes.clone(), false) {
                Ok(()) => {
                    // 成功发送，清空缓冲区
                    self.write_buf.clear();
                    Poll::Ready(Ok(buf.len()))
                }
                Err(e) => {
                    // 检查是否是流控错误
                    if Self::is_flow_control_error(&e) {
                        // 流控错误，需要等待
                        // write_buf 已经包含数据，不需要重新添加
                        // 等待流控恢复，唤醒任务以便重试
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        // 其他错误（如连接关闭）
                        self.closed = true;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            format!("gRPC send error: {}", e),
                        )))
                    }
                }
            }
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // 确保所有待发送的数据都已发送
        while !self.write_buf.is_empty() {
            let frame = encode_grpc_message(&self.write_buf);
            let frame_bytes = frame.freeze();
            
            match self.send_stream.send_data(frame_bytes.clone(), false) {
                Ok(()) => {
                    // 成功发送，清空缓冲区
                    self.write_buf.clear();
                }
                Err(e) => {
                    // 检查是否是流控错误
                    if Self::is_flow_control_error(&e) {
                        // 流控错误，需要等待
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    } else {
                        // 其他错误（如连接关闭）
                        self.closed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            format!("gRPC send error: {}", e),
                        )));
                    }
                }
            }
        }
        
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        
        // 先刷新所有待发送的数据
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => {
                // 发送 gRPC 状态 trailers
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
        }
    }
}
