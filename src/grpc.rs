use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, BufMut, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use h2::{server, SendStream, RecvStream, Reason, Ping};
use http::{Response, StatusCode};
use anyhow::Result;
use futures_util::Future;
use tokio::sync::Semaphore;
use tracing::{warn, debug};

const READ_BUFFER_SIZE: usize = 256 * 1024;
const WRITE_BUFFER_SIZE: usize = 128 * 1024;
const MAX_CONCURRENT_STREAMS: usize = 100;
const MAX_HEADER_LIST_SIZE: u32 = 2 * 1024;
const INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 2 * 1024 * 1024;
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;

// PING 心跳相关常量
const PING_INTERVAL_SECS: u64 = 30;
const PING_TIMEOUT_SECS: u64 = 10;
const MAX_MISSED_PINGS: u32 = 3;

/// gRPC HTTP/2 连接管理器
/// 
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    stream_semaphore: Arc<Semaphore>,
    active_count: Arc<AtomicUsize>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;
        
        // 注意：h2 库的并发流限制通过信号量在应用层控制
        // HTTP/2 协议本身也有流控机制
        
        Ok(Self { 
            h2_conn,
            stream_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
            active_count: Arc::new(AtomicUsize::new(0)),
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
        let active_count = self.active_count;
        let mut last_activity_time = std::time::Instant::now();
        
        let mut ping_pong = h2_conn.ping_pong();
        
        let mut ping_state = PingState::Idle;
        let mut missed_pings: u32 = 0;
        let mut ping_timer = tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
        ping_timer.tick().await;
        
        loop {
            tokio::select! {
                // 处理新的 HTTP/2 流请求
                result = h2_conn.accept() => {
                    match result {
                        Some(Ok((request, mut respond))) => {
                            last_activity_time = std::time::Instant::now();
                            missed_pings = 0;
                            
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
                                .header("te", "trailers")
                                .header("grpc-accept-encoding", "identity,deflate,gzip")
                                .body(())
                                .unwrap();

                            let send_stream = match respond.send_response(response, false) {
                                Ok(stream) => stream,
                                Err(e) => {
                                    warn!(error = %e, "Failed to send gRPC response");
                                    continue;
                                }
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
                                read_buf: Bytes::new(),
                                read_pos: 0,
                                write_buf: BytesMut::with_capacity(WRITE_BUFFER_SIZE),
                                closed: false,
                            };

                            let handler_clone = Arc::clone(&handler);
                            let active_count_clone = Arc::clone(&active_count);
                            active_count_clone.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(_e) = handler_clone(transport).await {
                                    // 记录流处理错误，但不影响其他流
                                }
                                active_count_clone.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error, closing connection");
                            return Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            // 正常关闭
                            debug!("gRPC connection closed normally");
                            break;
                        }
                    }
                }
                
                // 定期心跳检查
                _ = ping_timer.tick() => {
                    let idle_time = last_activity_time.elapsed();
                    let current_active = active_count.load(Ordering::Relaxed);
                    
                    if idle_time.as_secs() >= CONNECTION_IDLE_TIMEOUT_SECS && current_active == 0 {
                        warn!(
                            idle_secs = idle_time.as_secs(), 
                            active_count = current_active,
                            "gRPC connection idle timeout with no active streams, closing"
                        );
                        break;
                    }
                    
                    if let Some(ref mut pp) = ping_pong {
                        match &ping_state {
                            PingState::Idle => {
                                let ping = Ping::opaque();
                                if let Err(e) = pp.send_ping(ping) {
                                    warn!(error = %e, "Failed to send HTTP/2 PING");
                                } else {
                                    ping_state = PingState::WaitingPong(std::time::Instant::now());
                                    debug!("Sent HTTP/2 PING frame");
                                }
                            }
                            PingState::WaitingPong(sent_time) => {
                                // 检查上一个 PING 是否超时
                                if sent_time.elapsed().as_secs() >= PING_TIMEOUT_SECS {
                                    missed_pings += 1;
                                    warn!(
                                        missed_pings = missed_pings,
                                        max_missed = MAX_MISSED_PINGS,
                                        "HTTP/2 PING timeout, no PONG received"
                                    );
                                    
                                    if missed_pings >= MAX_MISSED_PINGS {
                                        warn!("Too many missed PING responses, connection appears dead");
                                        return Err(anyhow::anyhow!("gRPC heartbeat timeout"));
                                    }
                                    
                                    ping_state = PingState::Idle;
                                }
                            }
                        }
                    }
                }
                
                // 等待 PONG 响应
                pong_result = poll_pong_if_waiting(&mut ping_pong, &ping_state) => {
                    match pong_result {
                        Some(Ok(_pong)) => {
                            ping_state = PingState::Idle;
                            missed_pings = 0;
                            last_activity_time = std::time::Instant::now();
                            debug!("Received HTTP/2 PONG response");
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "HTTP/2 PONG receive error");
                            return Err(anyhow::anyhow!("gRPC PONG error: {}", e));
                        }
                        None => {
                            // 不在等待状态，继续
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
enum PingState {
    Idle,
    WaitingPong(std::time::Instant),
}

async fn poll_pong_if_waiting(
    ping_pong: &mut Option<h2::PingPong>,
    ping_state: &PingState,
) -> Option<Result<h2::Pong, h2::Error>> {
    if !matches!(ping_state, PingState::WaitingPong(_)) {
        return std::future::pending().await;
    }
    
    if let Some(ref mut pp) = ping_pong {
        let result = futures_util::future::poll_fn(|cx| pp.poll_pong(cx)).await;
        Some(result)
    } else {
        std::future::pending().await
    }
}

/// gRPC 传输层（兼容 v2ray）
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    recv_stream: RecvStream,
    send_stream: SendStream<Bytes>,
    read_pending: BytesMut,
    read_buf: Bytes,
    read_pos: usize,
    write_buf: BytesMut,
    closed: bool,
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
                    
                    // 直接复制到目标缓冲区，避免中间分配
                    buf.put_slice(&payload[..to_copy]);
                    
                    // 如果有剩余数据，保存起来
                    if to_copy < payload.len() {
                        self.read_buf = Bytes::copy_from_slice(&payload[to_copy..]);
                        self.read_pos = 0;
                    }
                    
                    if let Err(e) = self.recv_stream.flow_control().release_capacity(consumed) {
                        warn!(error = %e, consumed = consumed, "Failed to release HTTP/2 flow control capacity");
                    }
                    self.read_pending.advance(consumed);
                    
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }

            let poll_result = {
                let mut data_future = Box::pin(self.recv_stream.data());
                data_future.as_mut().poll(cx)
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

        if self.write_buf.len() + buf.len() > WRITE_BUFFER_SIZE {
            match self.try_send_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        
        self.write_buf.extend_from_slice(buf);
        
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
    fn try_send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let frame = encode_grpc_message(&self.write_buf);
        let frame_len = frame.len();
        
        loop {
            let capacity = self.send_stream.capacity();
            if capacity >= frame_len {
                break;
            }
            
            self.send_stream.reserve_capacity(frame_len);
            match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => {
                    continue;
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
