use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use h2::{server};
use http::{Response, StatusCode};
use anyhow::Result;

// 通道缓冲区大小，限制内存占用
const CHANNEL_BUFFER_SIZE: usize = 32;
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

                    let mut send_stream = match respond.send_response(response, false) {
                        Ok(stream) => stream,
                        Err(_) => continue,
                    };

                    let mut recv_stream = request.into_body();

                    // 创建有界数据通道，限制内存占用
                    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
                    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);

                    // 读取任务：从 gRPC 流中解析数据
                    tokio::spawn(async move {
                        let mut pending = BytesMut::new();
                        loop {
                            match recv_stream.data().await {
                                Some(Ok(chunk)) => {
                                    // 释放流控容量
                                    recv_stream.flow_control().release_capacity(chunk.len())
                                        .unwrap_or_else(|e| {
                                            eprintln!("[gRPC] Failed to release capacity: {}", e);
                                        });
                                    
                                    // 限制 pending 缓冲区大小，防止内存溢出
                                    if pending.len() + chunk.len() > MAX_PENDING_SIZE {
                                        eprintln!("[gRPC] Pending buffer too large ({}), dropping connection", pending.len());
                                        break;
                                    }
                                    
                                    pending.extend_from_slice(&chunk);
                                    
                                    // 循环解析完整的 gRPC 消息
                                    loop {
                                        match parse_grpc_message(&pending) {
                                            Ok(Some((consumed, payload))) => {
                                                // 如果通道满了，等待空间或丢弃
                                                match read_tx.try_send(payload) {
                                                    Ok(_) => {
                                                        pending.advance(consumed);
                                                    }
                                                    Err(mpsc::error::TrySendError::Full(payload)) => {
                                                        // 通道满了，等待一下再试
                                                        tokio::task::yield_now().await;
                                                        // 如果还是满的，丢弃这个包以避免内存溢出
                                                        if read_tx.try_send(payload).is_err() {
                                                            eprintln!("[gRPC] Channel full, dropping message");
                                                            pending.advance(consumed);
                                                        }
                                                    }
                                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                                        return;
                                                    }
                                                }
                                            }
                                            Ok(None) => {
                                                // 数据不足，等待更多数据
                                                break;
                                            }
                                            Err(e) => {
                                                eprintln!("[gRPC] Parse error: {}", e);
                                                // 跳过错误字节，尝试恢复
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
                                    // 忽略正常的流结束信号
                                    if !e.to_string().contains("not a result of an error") {
                                        eprintln!("[gRPC] Recv error: {}", e);
                                    }
                                    break;
                                }
                                None => break,
                            }
                        }
                    });

                    // 写入任务：将数据编码为 gRPC 格式并发送
                    tokio::spawn(async move {
                        while let Some(payload) = write_rx.recv().await {
                            let frame = encode_grpc_message(&payload);
                            if send_stream.send_data(frame.freeze(), false).is_err() {
                                break;
                            }
                        }
                        // 发送 gRPC 状态 trailers
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        let _ = send_stream.send_trailers(trailers);
                    });

                    // 为每个流创建传输层并启动处理任务
                    let transport = GrpcH2cTransport {
                        read_rx,
                        write_tx,
                        read_buf: Vec::new(),
                        read_pos: 0,
                        closed: false,
                        pending_write: None,
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
pub struct GrpcH2cTransport {
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    closed: bool,
    // 用于背压处理：当通道满时暂存的数据
    pending_write: Option<Vec<u8>>,
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
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed"
            )));
        }

        // 如果有待发送的数据，先尝试发送
        if let Some(pending) = self.pending_write.take() {
            match self.write_tx.try_send(pending) {
                Ok(_) => {
                    // 待发送数据已发送，继续处理新数据
                }
                Err(mpsc::error::TrySendError::Full(data)) => {
                    // 通道还是满的，把数据放回去
                    self.pending_write = Some(data);
                    // 不立即唤醒，等待接收端消费数据后自然唤醒
                    // 这样可以避免忙等待，减少 CPU 占用
                    return Poll::Pending;
                }
                Err(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "write channel closed"
                    )));
                }
            }
        }

        // 尝试发送新数据
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(data)) => {
                // 通道满了，保存数据等待下次重试
                // 对于 TCP 传输，我们应该等待而不是丢弃数据
                self.pending_write = Some(data);
                // 不立即唤醒，等待接收端消费数据后自然唤醒
                // 当接收端从通道接收数据后，会触发下一次 poll，此时可以重试
                Poll::Pending
            }
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
