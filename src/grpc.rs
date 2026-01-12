use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use h2::{server, SendStream, Reason, FlowControl};
use http::{Response, StatusCode};
use anyhow::Result;
use tokio::sync::{Semaphore, mpsc};
use tracing::warn;

const READ_BUFFER_SIZE: usize = 256 * 1024;
const WRITE_BUFFER_SIZE: usize = 512 * 1024;
const MAX_CONCURRENT_STREAMS: usize = 100;
const MAX_HEADER_LIST_SIZE: u32 = 2 * 1024;
const MAX_GRPC_PAYLOAD_SIZE: usize = 64 * 1024;
const MAX_FRAMES_PER_POLL: usize = 16;

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
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .handshake(stream)
            .await
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
        const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300; // 5分钟无新流则关闭连接
        
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let stream_semaphore = self.stream_semaphore;
        let mut last_stream_time = std::time::Instant::now();
        let active_streams = Arc::new(AtomicUsize::new(0));
        
        loop {
            let accept_future = h2_conn.accept();
            let timeout_future = tokio::time::sleep(tokio::time::Duration::from_secs(30));
            
            tokio::select! {
                result = accept_future => {
                    match result {
                        Some(Ok((request, mut respond))) => {
                            last_stream_time = std::time::Instant::now();
                            
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
                                Err(e) => {
                                    warn!(error = %e, "Failed to send gRPC response");
                                    continue;
                                }
                            };

                            let mut recv_stream = request.into_body();
                            let flow_control: _ = recv_stream.flow_control().clone();

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

                            // 创建 channel 用于后台任务传递数据
                            // 不立即释放容量，延迟到真正消费后
                            let (recv_tx, recv_rx) = mpsc::channel(32);
                            
                            tokio::spawn(async move {
                                loop {
                                    match recv_stream.data().await {
                                        Some(Ok(chunk)) => {
                                            // 不立即释放容量，延迟到真正消费后
                                            if recv_tx.send(Ok(chunk)).await.is_err() {
                                                // receiver 已关闭
                                                break;
                                            }
                                        }
                                        Some(Err(e)) => {
                                            let _ = recv_tx.send(Err(e)).await;
                                            break;
                                        }
                                        None => {
                                            break;
                                        }
                                    }
                                }
                            });

                            let transport = GrpcH2cTransport {
                                send_stream,
                                read_pending: BytesMut::with_capacity(READ_BUFFER_SIZE),
                                read_buf: Bytes::new(),
                                read_pos: 0,
                                write_buf: BytesMut::with_capacity(WRITE_BUFFER_SIZE),
                                closed: false,
                                recv_rx,
                                flow_control,
                                received_bytes: 0,
                                released_bytes: 0,
                            };

                            let handler_clone = Arc::clone(&handler);
                            let active_streams_clone = Arc::clone(&active_streams);
                            active_streams_clone.fetch_add(1, Ordering::Relaxed);
                            
                            tokio::spawn(async move {
                                let _permit = permit;
                                let result = handler_clone(transport).await;
                                active_streams_clone.fetch_sub(1, Ordering::Relaxed);
                                if let Err(_e) = result {
                                    // 记录流处理错误，不影响其他流
                                }
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error, closing connection");
                            return Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            // 正常关闭
                            break;
                        }
                    }
                }
                _ = timeout_future => {
                    let idle_time = last_stream_time.elapsed();
                    let active_count = active_streams.load(Ordering::Relaxed);
                    if idle_time.as_secs() >= CONNECTION_IDLE_TIMEOUT_SECS && active_count == 0 {
                        warn!(idle_secs = idle_time.as_secs(), "gRPC connection idle timeout (no new streams for 5 min, no active streams), closing");
                        break;
                    }
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
    send_stream: SendStream<Bytes>,
    read_pending: BytesMut,
    read_buf: Bytes,
    read_pos: usize,
    write_buf: BytesMut,
    closed: bool,
    recv_rx: mpsc::Receiver<Result<Bytes, h2::Error>>,
    flow_control: FlowControl,
    received_bytes: usize,  // 累计已接收的字节数（从 channel 接收的）
    released_bytes: usize,  // 累计已释放的字节数（从 read_pending advance 后释放的）
}

/// 解析 gRPC 消息帧（兼容 v2ray 格式）
/// 
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
fn parse_grpc_message(buf: &BytesMut) -> io::Result<Option<(usize, &[u8])>> {
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

    let payload = &buf[data_start..data_end];
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
                self.read_buf = Bytes::new();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match parse_grpc_message(&self.read_pending) {
                Ok(Some((consumed, payload))) => {
                    let to_copy = payload.len().min(buf.remaining());
                    let payload_data = Bytes::copy_from_slice(&payload[..to_copy]);
                    let remaining_data = if to_copy < payload.len() {
                        Some(Bytes::copy_from_slice(&payload[to_copy..]))
                    } else {
                        None
                    };
                    
                    // 真正消费：从 read_pending 中 advance 掉 consumed 字节
                    self.read_pending.advance(consumed);
                    
                    // 释放对应的容量：当 gRPC frame 的字节已经从 read_pending 中 advance 掉
                    // 释放的容量不能超过已接收的容量
                    let to_release = consumed.min(self.received_bytes - self.released_bytes);
                    if to_release > 0 {
                        let _ = self.flow_control.release_capacity(to_release);
                        self.released_bytes += to_release;
                    }
                    
                    buf.put_slice(&payload_data);
                    
                    if let Some(remaining) = remaining_data {
                        self.read_buf = remaining;
                        self.read_pos = 0;
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }

            // 从 channel 接收数据，由后台任务发送
            match self.recv_rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.read_pending.extend_from_slice(&chunk);
                    // 记录累计的已接收容量，等待真正消费后释放
                    self.received_bytes += chunk.len();
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
                    // channel 关闭，流已结束
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

        if self.write_buf.len() + buf.len() > WRITE_BUFFER_SIZE {
            return Poll::Pending;
        }
        
        self.write_buf.extend_from_slice(buf);
        
        match self.try_send_pending(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
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
    fn try_send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let mut sent = 0;
        while sent < MAX_FRAMES_PER_POLL && !self.write_buf.is_empty() {
            match self.try_send_one_frame(cx) {
                Poll::Ready(Ok(true)) => {
                    sent += 1;
                }
                Poll::Ready(Ok(false)) => {
                    // 没有数据可发送
                    break;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
        
        Poll::Ready(Ok(()))
    }
    
    fn try_send_one_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(false));
        }

        let payload_size = self.write_buf.len().min(MAX_GRPC_PAYLOAD_SIZE);
        let payload = &self.write_buf[..payload_size];
        
        let frame = encode_grpc_message(payload);
        let frame_len = frame.len();
        
        let capacity = self.send_stream.capacity();
        if capacity < frame_len {
            self.send_stream.reserve_capacity(frame_len);
            match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {
                    // 容量已准备好，继续发送
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("gRPC capacity error: {}", e),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "gRPC stream closed",
                    )));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
        
        let frame_bytes = frame.freeze();
        match self.send_stream.send_data(frame_bytes, false) {
            Ok(()) => {
                // 只清除已发送的数据，保留剩余数据
                self.write_buf.advance(payload_size);
                Poll::Ready(Ok(true))
            }
            Err(e) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("gRPC send error: {}", e),
            ))),
        }
    }
}
