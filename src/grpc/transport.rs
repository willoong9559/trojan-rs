use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{Buf, Bytes, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;
use h2::{SendStream, RecvStream, Reason};
use tracing::warn;

use super::codec::{encode_grpc_message, parse_grpc_header};
use super::{
    MAX_FRAME_SIZE, GRPC_MAX_MESSAGE_SIZE, MAX_SEND_QUEUE_BYTES, READ_BUFFER_SIZE,
    STREAM_WRITE_TIMEOUT_SECS,
};

/// gRPC 传输层（兼容 v2ray）
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) send_stream: SendStream<Bytes>,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_remaining: usize,
    pub(crate) pending_release_capacity: usize,
    pub(crate) send_queue: VecDeque<Bytes>,
    pub(crate) send_queue_bytes: usize,
    pub(crate) current_frame: Option<Bytes>,
    pub(crate) current_frame_offset: usize,
    pub(crate) write_wait_timeout: Option<Pin<Box<tokio::time::Sleep>>>,
    pub(crate) closed: bool,
    pub(crate) trailers_sent: bool,
}

impl GrpcH2cTransport {
    pub(crate) fn new(recv_stream: RecvStream, send_stream: SendStream<Bytes>) -> Self {
        Self {
            recv_stream,
            send_stream,
            read_pending: BytesMut::with_capacity(READ_BUFFER_SIZE),
            read_remaining: 0,
            pending_release_capacity: 0,
            send_queue: VecDeque::new(),
            send_queue_bytes: 0,
            current_frame: None,
            current_frame_offset: 0,
            write_wait_timeout: None,
            closed: false,
            trailers_sent: false,
        }
    }

    fn poll_send_queued(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref frame) = self.current_frame {
                if self.current_frame_offset > frame.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid send state: frame offset exceeds frame length",
                    )));
                }
                let remaining = frame.len() - self.current_frame_offset;
                if remaining > 0 {
                    let frame_len = frame.len();
                    match self.poll_send_current_frame(cx)? {
                        Poll::Ready(()) => {
                            self.send_queue_bytes = self.send_queue_bytes.saturating_sub(frame_len);
                            self.current_frame = None;
                            self.current_frame_offset = 0;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                } else {
                    self.current_frame = None;
                    self.current_frame_offset = 0;
                }
            }

            match self.send_queue.pop_front() {
                Some(frame) => {
                    self.current_frame = Some(frame);
                    self.current_frame_offset = 0;
                }
                None => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_send_current_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let frame = match &self.current_frame {
            Some(f) => f,
            None => return Poll::Ready(Ok(())),
        };

        if self.current_frame_offset > frame.len() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid send state: frame offset exceeds frame length",
            )));
        }

        loop {
            let remaining = frame.len() - self.current_frame_offset;
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let capacity = self.send_stream.capacity();
            if capacity == 0 {
                if self.write_wait_timeout.is_none() {
                    self.write_wait_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(
                        STREAM_WRITE_TIMEOUT_SECS,
                    ))));
                }
                self.send_stream.reserve_capacity(remaining.min(MAX_FRAME_SIZE as usize));
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => {
                        self.write_wait_timeout = None;
                        continue;
                    }
                    Poll::Ready(Some(Ok(_))) | Poll::Pending => {
                        if self.write_wait_timed_out(cx) {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "gRPC stream write stalled waiting for flow-control capacity",
                            )));
                        }
                        return Poll::Pending;
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
                }
            }

            let send_size = remaining.min(capacity);
            let chunk = frame.slice(self.current_frame_offset..self.current_frame_offset + send_size);
            
            match self.send_stream.send_data(chunk, false) {
                Ok(()) => {
                    self.write_wait_timeout = None;
                    self.current_frame_offset += send_size;
                    if self.current_frame_offset >= frame.len() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )));
                }
            }
        }
    }

    fn poll_wait_send_capacity(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_wait_timeout.is_none() {
            self.write_wait_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(
                STREAM_WRITE_TIMEOUT_SECS,
            ))));
        }
        self.send_stream.reserve_capacity(MAX_FRAME_SIZE as usize);
        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(cap))) if cap > 0 => {
                self.write_wait_timeout = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {
                if self.write_wait_timed_out(cx) {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "gRPC send queue saturated and no flow-control progress",
                    )))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("gRPC capacity error: {}", e),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC stream closed",
            ))),
        }
    }

    fn write_wait_timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        if let Some(timeout) = &mut self.write_wait_timeout {
            return timeout.as_mut().poll(cx).is_ready();
        }
        false
    }
}

fn is_normal_stream_close(error: &h2::Error) -> bool {
    if let Some(reason) = error.reason() {
        matches!(reason, Reason::NO_ERROR | Reason::CANCEL)
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

        loop {
            if self.read_remaining > 0 {
                if !self.read_pending.is_empty() {
                    let to_copy = self
                        .read_remaining
                        .min(buf.remaining())
                        .min(self.read_pending.len());
                    buf.put_slice(&self.read_pending[..to_copy]);
                    self.read_pending.advance(to_copy);
                    self.read_remaining -= to_copy;
                    self.release_flow_control_capacity(to_copy);
                    return Poll::Ready(Ok(()));
                }

                match self.poll_recv_data(cx) {
                    Poll::Ready(Ok(true)) => continue,
                    Poll::Ready(Ok(false)) => {
                        if self.read_remaining > 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "gRPC stream closed in the middle of a message payload",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match parse_grpc_header(&self.read_pending) {
                    Ok(Some(header)) => {
                        self.read_pending.advance(header.header_len);
                        self.release_flow_control_capacity(header.header_len);
                        self.read_remaining = header.payload_len;
                        if self.read_remaining == 0 {
                            continue;
                        }
                    }
                    Ok(None) => match self.poll_recv_data(cx) {
                        Poll::Ready(Ok(true)) => continue,
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    },
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
    }
}

impl GrpcH2cTransport {
    fn release_flow_control_capacity(&mut self, amount: usize) {
        if amount == 0 || self.pending_release_capacity == 0 {
            return;
        }
        let to_release = self.pending_release_capacity.min(amount);
        if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release) {
            warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
        }
        self.pending_release_capacity -= to_release;
    }

    // 返回:
    // - Ok(true): 读取到了新数据
    // - Ok(false): 对端正常关闭
    fn poll_recv_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self.recv_stream.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = chunk.len();
                if self.read_pending.len() + chunk_len > READ_BUFFER_SIZE {
                    warn!(
                        pending = self.read_pending.len(),
                        incoming = chunk_len,
                        limit = READ_BUFFER_SIZE,
                        "gRPC read buffer overflow"
                    );
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "gRPC read buffer overflow",
                    )));
                }
                self.read_pending.extend_from_slice(&chunk);
                self.pending_release_capacity += chunk_len;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Some(Err(e))) => {
                self.closed = true;
                if is_normal_stream_close(&e) {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("gRPC recv error: {}", e),
                    )))
                }
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(false))
            }
            Poll::Pending => Poll::Pending,
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

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.poll_send_queued(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if self.send_queue_bytes >= MAX_SEND_QUEUE_BYTES {
            match self.poll_wait_send_capacity(cx) {
                Poll::Ready(Ok(())) => {
                    match self.poll_send_queued(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    if self.send_queue_bytes >= MAX_SEND_QUEUE_BYTES {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "gRPC send queue is saturated without progress",
                        )));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let to_write = buf.len().min(GRPC_MAX_MESSAGE_SIZE);
        let frame = encode_grpc_message(&buf[..to_write]);
        let frame_bytes = frame.len();
        self.send_queue.push_back(frame.freeze());
        self.send_queue_bytes += frame_bytes;

        match self.poll_send_queued(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_send_queued(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;

        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                if self.current_frame.is_some() || !self.send_queue.is_empty() {
                    return Poll::Pending;
                }

                if self.trailers_sent {
                    return Poll::Ready(Ok(()));
                }

                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                match self.send_stream.send_trailers(trailers) {
                    Ok(()) => {
                        self.trailers_sent = true;
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => {
                        self.trailers_sent = true;
                        if e.is_remote() || e.is_io() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("gRPC send trailers error: {}", e),
                            )))
                        }
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::GrpcH2cConnection;
    use bytes::Bytes;
    use futures_util::future::poll_fn;
    use h2::client;
    use http::Request;
    use std::env;
    use std::time::Instant;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::{oneshot, Mutex};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn transport_write_all_succeeds() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
        let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));
        let payload = std::sync::Arc::new(vec![0xAB; 40 * 1024]);

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            let _ = conn
                .run({
                    let done_tx = std::sync::Arc::clone(&done_tx);
                    let payload = std::sync::Arc::clone(&payload);
                    move |mut transport| {
                        let done_tx = std::sync::Arc::clone(&done_tx);
                        let payload = std::sync::Arc::clone(&payload);
                        async move {
                            let result = timeout(Duration::from_secs(3), transport.write_all(&payload))
                                .await
                                .map_err(|_| "write_all timeout".to_string())
                                .and_then(|r| r.map_err(|e| format!("write_all error: {e}")))
                                .map(|_| ());
                            if let Some(tx) = done_tx.lock().await.take() {
                                let _ = tx.send(result);
                            }
                            Ok(())
                        }
                    }
                })
                .await;
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, _request_stream) = send_request
            .send_request(request, true)
            .expect("request send should succeed");
        let response = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");
        let mut body = response.into_body();
        let body_drain_task = tokio::spawn(async move {
            loop {
                match poll_fn(|cx| body.poll_data(cx)).await {
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
        });

        let result = timeout(Duration::from_secs(3), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        body_drain_task.abort();
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn queue_full_path_must_not_hang_write() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
        let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            let _ = conn
                .run({
                    let done_tx = std::sync::Arc::clone(&done_tx);
                    move |mut transport| {
                        let done_tx = std::sync::Arc::clone(&done_tx);
                        async move {
                            transport.send_queue_bytes = MAX_SEND_QUEUE_BYTES;
                            let result = timeout(Duration::from_millis(300), transport.write_all(b"hello"))
                                .await
                                .map_err(|_| "write_all hung in queue-full path".to_string())
                                .map(|_| ());
                            if let Some(tx) = done_tx.lock().await.take() {
                                let _ = tx.send(result);
                            }
                            Ok(())
                        }
                    }
                })
                .await;
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, _request_stream) = send_request
            .send_request(request, true)
            .expect("request send should succeed");
        let response = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");
        let mut body = response.into_body();
        let body_drain_task = tokio::spawn(async move {
            loop {
                match poll_fn(|cx| body.poll_data(cx)).await {
                    Some(Ok(chunk)) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(_)) | None => break,
                }
            }
        });

        let result = timeout(Duration::from_secs(3), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        body_drain_task.abort();
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn burst_writes_should_complete_without_stall() {
        let (server_io, client_io) = tokio::io::duplex(8 * 1024 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
        let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));
        let payload = std::sync::Arc::new(vec![0x5A; 8 * 1024]);
        let iterations = 64usize;

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            let _ = conn
                .run({
                    let done_tx = std::sync::Arc::clone(&done_tx);
                    let payload = std::sync::Arc::clone(&payload);
                    move |mut transport| {
                        let done_tx = std::sync::Arc::clone(&done_tx);
                        let payload = std::sync::Arc::clone(&payload);
                        async move {
                            let result = timeout(Duration::from_secs(5), async {
                                for _ in 0..iterations {
                                    transport.write_all(&payload).await?;
                                }
                                transport.flush().await?;
                                Ok::<(), io::Error>(())
                            })
                            .await
                            .map_err(|_| "burst writes timeout".to_string())
                            .and_then(|r| match r {
                                Ok(()) => Ok(()),
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        io::ErrorKind::TimedOut
                                            | io::ErrorKind::WouldBlock
                                            | io::ErrorKind::BrokenPipe
                                    ) =>
                                {
                                    Ok(())
                                }
                                Err(e) => Err(format!("unexpected burst error: {e}")),
                            });
                            if let Some(tx) = done_tx.lock().await.take() {
                                let _ = tx.send(result);
                            }
                            Ok(())
                        }
                    }
                })
                .await;
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, _request_stream) = send_request
            .send_request(request, true)
            .expect("request send should succeed");
        let response = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");
        let mut body = response.into_body();
        let body_drain_task = tokio::spawn(async move {
            loop {
                match poll_fn(|cx| body.poll_data(cx)).await {
                    Some(Ok(chunk)) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    Some(Err(_)) | None => break,
                }
            }
        });

        let result = timeout(Duration::from_secs(6), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        body_drain_task.abort();
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn queue_full_returns_wouldblock_error() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
        let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            let _ = conn
                .run({
                    let done_tx = std::sync::Arc::clone(&done_tx);
                    move |mut transport| {
                        let done_tx = std::sync::Arc::clone(&done_tx);
                        async move {
                            transport.send_queue_bytes = MAX_SEND_QUEUE_BYTES;
                            let result = timeout(Duration::from_secs(1), transport.write(b"hello"))
                                .await
                                .map_err(|_| "write timeout".to_string())
                                .and_then(|r| match r {
                                    Ok(_) => Err("expected WouldBlock but write succeeded".to_string()),
                                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
                                    Err(e) => Err(format!("expected WouldBlock, got: {e}")),
                                });
                            if let Some(tx) = done_tx.lock().await.take() {
                                let _ = tx.send(result);
                            }
                            Ok(())
                        }
                    }
                })
                .await;
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, _request_stream) = send_request
            .send_request(request, true)
            .expect("request send should succeed");
        let _ = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");

        let result = timeout(Duration::from_secs(3), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn shutdown_should_be_idempotent() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
        let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            let _ = conn
                .run({
                    let done_tx = std::sync::Arc::clone(&done_tx);
                    move |mut transport| {
                        let done_tx = std::sync::Arc::clone(&done_tx);
                        async move {
                            let result = timeout(Duration::from_secs(3), async {
                                transport.shutdown().await?;
                                transport.shutdown().await?;
                                Ok::<(), io::Error>(())
                            })
                            .await
                            .map_err(|_| "shutdown timeout".to_string())
                            .and_then(|r| r.map_err(|e| format!("shutdown error: {e}")));
                            if let Some(tx) = done_tx.lock().await.take() {
                                let _ = tx.send(result);
                            }
                            Ok(())
                        }
                    }
                })
                .await;
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, _request_stream) = send_request
            .send_request(request, true)
            .expect("request send should succeed");
        let _ = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");

        let result = timeout(Duration::from_secs(3), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn stress_profile_multi_stream() {
        let streams = env::var("GRPC_STRESS_STREAMS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(32);
        let iterations = env::var("GRPC_STRESS_ITERATIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(128);
        let payload_bytes = env::var("GRPC_STRESS_PAYLOAD_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(8 * 1024);
        let timeout_secs = env::var("GRPC_STRESS_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);

        let start = Instant::now();
        let mut tasks = Vec::with_capacity(streams);
        for idx in 0..streams {
            tasks.push(tokio::spawn(async move {
                let (server_io, client_io) = tokio::io::duplex(8 * 1024 * 1024);
                let (done_tx, done_rx) = oneshot::channel::<Result<(), String>>();
                let done_tx = std::sync::Arc::new(Mutex::new(Some(done_tx)));
                let payload = std::sync::Arc::new(vec![0x3C; payload_bytes]);

                let server_task = tokio::spawn(async move {
                    let conn = GrpcH2cConnection::new(server_io)
                        .await
                        .expect("server handshake should succeed");
                    let _ = conn
                        .run({
                            let done_tx = std::sync::Arc::clone(&done_tx);
                            let payload = std::sync::Arc::clone(&payload);
                            move |mut transport| {
                                let done_tx = std::sync::Arc::clone(&done_tx);
                                let payload = std::sync::Arc::clone(&payload);
                                async move {
                                    let result = timeout(Duration::from_secs(timeout_secs), async {
                                        for _ in 0..iterations {
                                            transport.write_all(&payload).await?;
                                        }
                                        transport.flush().await?;
                                        Ok::<(), io::Error>(())
                                    })
                                    .await
                                    .map_err(|_| format!("stream-{idx} timeout"))
                                    .and_then(|r| r.map_err(|e| format!("stream-{idx} write error: {e}")));
                                    if let Some(tx) = done_tx.lock().await.take() {
                                        let _ = tx.send(result);
                                    }
                                    Ok(())
                                }
                            }
                        })
                        .await;
                });

                let (mut send_request, client_conn) = client::Builder::new()
                    .handshake::<_, Bytes>(client_io)
                    .await
                    .map_err(|e| format!("stream-{idx} client handshake: {e}"))?;
                let client_conn_task = tokio::spawn(async move {
                    let _ = client_conn.await;
                });

                let request = Request::builder()
                    .method("POST")
                    .uri("/Tun")
                    .body(())
                    .map_err(|e| format!("stream-{idx} request build: {e}"))?;
                let (response_future, _request_stream) = send_request
                    .send_request(request, true)
                    .map_err(|e| format!("stream-{idx} send request: {e}"))?;
                let response = timeout(Duration::from_secs(3), response_future)
                    .await
                    .map_err(|_| format!("stream-{idx} response header timeout"))?
                    .map_err(|e| format!("stream-{idx} response future: {e}"))?;
                let mut body = response.into_body();
                let body_drain_task = tokio::spawn(async move {
                    loop {
                        match poll_fn(|cx| body.poll_data(cx)).await {
                            Some(Ok(chunk)) => {
                                let _ = body.flow_control().release_capacity(chunk.len());
                            }
                            Some(Err(_)) | None => break,
                        }
                    }
                });

                let result = timeout(Duration::from_secs(timeout_secs + 2), done_rx)
                    .await
                    .map_err(|_| format!("stream-{idx} done timeout"))?
                    .map_err(|_| format!("stream-{idx} done channel closed"))?;

                body_drain_task.abort();
                server_task.abort();
                client_conn_task.abort();

                result?;
                Ok::<usize, String>(iterations * payload_bytes)
            }));
        }

        let mut total_bytes = 0usize;
        let mut failures = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(bytes)) => total_bytes += bytes,
                Ok(Err(e)) => failures.push(e),
                Err(e) => failures.push(format!("join error: {e}")),
            }
        }

        let elapsed = start.elapsed();
        let throughput_mib = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        println!(
            "grpc-stress streams={} iterations={} payload={}B total={}B elapsed={:.3}s throughput={:.2}MiB/s failures={}",
            streams,
            iterations,
            payload_bytes,
            total_bytes,
            elapsed.as_secs_f64(),
            throughput_mib,
            failures.len()
        );

        assert!(
            failures.is_empty(),
            "stress failures: {}",
            failures.join(" | ")
        );
    }
}
