use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{Buf, Bytes, BytesMut};
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::io;
use h2::{SendStream, RecvStream, Reason};
use tracing::{debug, warn};

use crate::relay::{RelayIo, WriteBufferWatermark, WriteBufferWaker};

use super::codec::{encode_grpc_message, parse_grpc_header};
use super::{
    GRPC_MAX_MESSAGE_SIZE, STREAM_BUFFER_HIGH_WATERMARK, STREAM_BUFFER_LOW_WATERMARK,
};

/// gRPC 传输层（兼容 v2ray）
/// 
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) send_stream: SendStream<Bytes>,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_remaining: usize,
    pub(crate) unconsumed_bytes: usize,
    pub(crate) pending_send_buffer: BytesMut,
    pub(crate) waiting_for_send_capacity: bool,
    pub(crate) read_disable_count: usize,
    pub(crate) recv_high_watermark_triggered: bool,
    pub(crate) send_high_watermark_triggered: bool,
    pub(crate) recv_closed: bool,
    pub(crate) send_closed: bool,
    pub(crate) trailers_sent: bool,
    connection_send_watermark: Arc<WriteBufferWatermark>,
    stream_write_waker: Arc<WriteBufferWaker>,
    read_waker: Option<Waker>,
}

impl GrpcH2cTransport {
    pub(crate) fn new(
        recv_stream: RecvStream,
        send_stream: SendStream<Bytes>,
        connection_send_watermark: Arc<WriteBufferWatermark>,
    ) -> Self {
        let stream_write_waker = Arc::new(WriteBufferWaker::default());
        connection_send_watermark.register_waker(&stream_write_waker);
        Self {
            recv_stream,
            send_stream,
            read_pending: BytesMut::new(),
            read_remaining: 0,
            unconsumed_bytes: 0,
            pending_send_buffer: BytesMut::new(),
            waiting_for_send_capacity: false,
            read_disable_count: 0,
            recv_high_watermark_triggered: false,
            send_high_watermark_triggered: false,
            recv_closed: false,
            send_closed: false,
            trailers_sent: false,
            connection_send_watermark,
            stream_write_waker,
            read_waker: None,
        }
    }

    fn replace_waker(slot: &mut Option<Waker>, waker: &Waker) {
        match slot {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    fn register_read_waker(&mut self, waker: &Waker) {
        Self::replace_waker(&mut self.read_waker, waker);
    }

    fn register_write_waker(&mut self, waker: &Waker) {
        self.stream_write_waker.register(waker);
    }

    fn wake_read_task(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn wake_write_task(&self) {
        self.stream_write_waker.wake();
    }

    fn poll_send_pending_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let remaining = self.pending_send_buffer.len();
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let capacity = self.send_stream.capacity();
            if capacity == 0 {
                if !self.waiting_for_send_capacity {
                    debug!(
                        queued_bytes = self.buffered_send_bytes(),
                        "Waiting for gRPC stream flow-control capacity",
                    );
                    self.waiting_for_send_capacity = true;
                }
                self.send_stream.reserve_capacity(remaining);
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => {
                        self.waiting_for_send_capacity = false;
                        continue;
                    }
                    Poll::Ready(Some(Ok(_))) | Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Err(e))) => {
                        self.waiting_for_send_capacity = false;
                        self.send_closed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("gRPC capacity error: {}", e),
                        )));
                    }
                    Poll::Ready(None) => {
                        self.waiting_for_send_capacity = false;
                        self.send_closed = true;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "gRPC stream closed",
                        )));
                    }
                }
            }

            let send_size = remaining.min(capacity);
            let chunk = self.pending_send_buffer.split_to(send_size).freeze();
            
            match self.send_stream.send_data(chunk, false) {
                Ok(()) => {
                    self.waiting_for_send_capacity = false;
                    self.update_send_watermarks();
                }
                Err(e) => {
                    self.send_closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("gRPC send error: {}", e),
                    )));
                }
            }
        }
    }

    fn buffered_read_bytes(&self) -> usize {
        self.read_pending.len()
    }

    fn buffered_send_bytes(&self) -> usize {
        self.pending_send_buffer.len()
    }

    fn buffers_overrun(&self) -> bool {
        self.read_disable_count > 0
    }

    fn should_allow_peer_additional_stream_window(&self) -> bool {
        !self.buffers_overrun() && !self.recv_high_watermark_triggered
    }

    fn maybe_grant_peer_additional_stream_window(&mut self) {
        if !self.should_allow_peer_additional_stream_window() {
            return;
        }
        self.grant_peer_additional_stream_window();
    }

    fn grant_peer_additional_stream_window(&mut self) {
        if self.unconsumed_bytes == 0 {
            return;
        }
        let amount = self.unconsumed_bytes;
        self.unconsumed_bytes = 0;
        if let Err(e) = self.recv_stream.flow_control().release_capacity(amount) {
            warn!(error = %e, amount, "Failed to release HTTP/2 flow control capacity");
        }
    }

    pub(crate) fn read_disable(&mut self, disable: bool) {
        if disable {
            let was_enabled = self.read_disable_count == 0;
            self.read_disable_count = self.read_disable_count.saturating_add(1);
            if was_enabled {
                debug!("gRPC reads disabled");
            }
            return;
        }

        if self.read_disable_count == 0 {
            return;
        }

        self.read_disable_count -= 1;
        if self.read_disable_count == 0 {
            debug!("gRPC reads re-enabled");
            self.maybe_grant_peer_additional_stream_window();
            self.wake_read_task();
        }
    }

    fn update_recv_watermarks(&mut self) {
        let buffered_read_bytes = self.buffered_read_bytes();
        if !self.recv_high_watermark_triggered
            && buffered_read_bytes >= STREAM_BUFFER_HIGH_WATERMARK
        {
            self.recv_high_watermark_triggered = true;
            debug!(
                buffered_read_bytes,
                "gRPC recv buffer reached high watermark",
            );
        } else if self.recv_high_watermark_triggered
            && buffered_read_bytes <= STREAM_BUFFER_LOW_WATERMARK
        {
            self.recv_high_watermark_triggered = false;
            debug!(
                buffered_read_bytes,
                "gRPC recv buffer dropped below low watermark",
            );
        }
    }

    fn recoup_unconsumed_bytes_on_close(&mut self) {
        self.recv_high_watermark_triggered = false;
        self.grant_peer_additional_stream_window();
    }

    fn update_send_watermarks(&mut self) {
        let queued_bytes = self.buffered_send_bytes();
        if !self.send_high_watermark_triggered
            && queued_bytes >= STREAM_BUFFER_HIGH_WATERMARK
        {
            self.send_high_watermark_triggered = true;
            debug!(queued_bytes, "gRPC send buffer reached high watermark");
        } else if self.send_high_watermark_triggered
            && queued_bytes <= STREAM_BUFFER_LOW_WATERMARK
        {
            self.send_high_watermark_triggered = false;
            debug!(queued_bytes, "gRPC send buffer dropped below low watermark");
            self.wake_write_task();
        }
    }

    fn enqueue_send_frame(&mut self, payload: &[u8]) {
        let frame = encode_grpc_message(payload);
        self.pending_send_buffer.extend_from_slice(&frame);
        self.update_send_watermarks();
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
        self.register_read_waker(cx.waker());

        if self.recv_closed && self.read_remaining == 0 && self.read_pending.is_empty() {
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
                    self.update_recv_watermarks();
                    self.maybe_grant_peer_additional_stream_window();
                    return Poll::Ready(Ok(()));
                }

                if self.recv_closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "gRPC stream closed in the middle of a message payload",
                    )));
                }

                if self.buffers_overrun() {
                    return Poll::Pending;
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
                        self.update_recv_watermarks();
                        self.maybe_grant_peer_additional_stream_window();
                        self.read_remaining = header.payload_len;
                        if self.read_remaining == 0 {
                            continue;
                        }
                    }
                    Ok(None) => {
                        if self.recv_closed {
                            return Poll::Ready(Ok(()));
                        }
                        if self.buffers_overrun() {
                            return Poll::Pending;
                        }
                        match self.poll_recv_data(cx) {
                            Poll::Ready(Ok(true)) => continue,
                            Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
    }
}

impl GrpcH2cTransport {
    // 返回:
    // - Ok(true): 读取到了新数据
    // - Ok(false): 对端正常关闭
    fn poll_recv_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self.recv_stream.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = chunk.len();
                self.read_pending.extend_from_slice(&chunk);
                self.unconsumed_bytes += chunk_len;
                self.update_recv_watermarks();
                self.maybe_grant_peer_additional_stream_window();
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Some(Err(e))) => {
                self.recv_closed = true;
                self.recoup_unconsumed_bytes_on_close();
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
                self.recv_closed = true;
                self.recoup_unconsumed_bytes_on_close();
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
        if self.send_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed"
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.register_write_waker(cx.waker());

        match self.poll_send_pending_buffer(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Pending => {
                if !self.pending_send_buffer.is_empty() {
                    return Poll::Pending;
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        self.update_send_watermarks();
        if self.send_high_watermark_triggered || self.connection_send_watermark.is_backpressured() {
            return Poll::Pending;
        }

        let to_write = buf.len().min(GRPC_MAX_MESSAGE_SIZE);
        self.enqueue_send_frame(&buf[..to_write]);

        match self.poll_send_pending_buffer(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }

        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.register_write_waker(cx.waker());
        match self.poll_send_pending_buffer(cx) {
            Poll::Ready(Ok(())) if self.connection_send_watermark.is_backpressured() => {
                Poll::Pending
            }
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.send_closed = true;

        if self.trailers_sent {
            return Poll::Ready(Ok(()));
        }

        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                if !self.pending_send_buffer.is_empty() {
                    return Poll::Pending;
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
                        if is_benign_trailer_send_error(&e) {
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

fn is_benign_trailer_send_error(error: &h2::Error) -> bool {
    error.is_remote()
        || error.is_io()
        || error.is_reset()
        || error.to_string().contains("unexpected frame type")
}

impl RelayIo for GrpcH2cTransport {
    fn read_disable(&mut self, disable: bool) {
        GrpcH2cTransport::read_disable(self, disable);
    }

    fn is_write_backpressured(&self) -> bool {
        self.connection_send_watermark.is_backpressured() || self.send_high_watermark_triggered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::GrpcH2cConnection;
    use bytes::Bytes;
    use futures_util::future::poll_fn;
    use futures_util::task::{waker, ArcWake};
    use h2::client;
    use http::Request;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{oneshot, Mutex};
    use tokio::time::{timeout, Duration};

    #[derive(Default)]
    struct CountingWaker {
        wake_count: AtomicUsize,
    }

    impl ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &std::sync::Arc<Self>) {
            arc_self.wake_count.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    #[test]
    fn connection_write_watermark_fans_out_to_all_streams() {
        let connection = WriteBufferWatermark::new(
            crate::relay::NETWORK_BUFFER_HIGH_WATERMARK,
            crate::relay::NETWORK_BUFFER_LOW_WATERMARK,
        );
        let stream_a = Arc::new(WriteBufferWaker::default());
        let stream_b = Arc::new(WriteBufferWaker::default());
        connection.register_waker(&stream_a);
        connection.register_waker(&stream_b);

        let counter_a = std::sync::Arc::new(CountingWaker::default());
        let counter_b = std::sync::Arc::new(CountingWaker::default());
        let waker_a = waker(counter_a.clone());
        let waker_b = waker(counter_b.clone());
        stream_a.register(&waker_a);
        stream_b.register(&waker_b);

        connection.update_buffered_bytes(0, crate::relay::NETWORK_BUFFER_HIGH_WATERMARK);
        assert!(connection.is_backpressured());
        assert_eq!(counter_a.wake_count.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(counter_b.wake_count.load(AtomicOrdering::Relaxed), 1);

        let waker_a = waker(counter_a.clone());
        let waker_b = waker(counter_b.clone());
        stream_a.register(&waker_a);
        stream_b.register(&waker_b);
        connection.update_buffered_bytes(
            crate::relay::NETWORK_BUFFER_HIGH_WATERMARK,
            crate::relay::NETWORK_BUFFER_LOW_WATERMARK,
        );
        assert!(!connection.is_backpressured());
        assert_eq!(counter_a.wake_count.load(AtomicOrdering::Relaxed), 2);
        assert_eq!(counter_b.wake_count.load(AtomicOrdering::Relaxed), 2);
    }

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
    async fn read_eof_must_not_close_write_half() {
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
                            let mut probe = [0u8; 1];
                            let result = timeout(Duration::from_secs(3), async {
                                let eof = transport.read(&mut probe).await?;
                                if eof != 0 {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("expected EOF, got {eof} bytes"),
                                    ));
                                }
                                transport.write_all(b"hello").await?;
                                transport.shutdown().await
                            })
                            .await
                            .map_err(|_| "server timeout".to_string())
                            .and_then(|r| r.map_err(|e| format!("server error: {e}")));
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

        let mut received = Vec::new();
        loop {
            match timeout(Duration::from_secs(3), poll_fn(|cx| body.poll_data(cx))).await {
                Ok(Some(Ok(chunk))) => {
                    received.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                Ok(Some(Err(e))) => panic!("response body error: {e}"),
                Ok(None) => break,
                Err(_) => panic!("response body timeout"),
            }
        }

        let result = timeout(Duration::from_secs(3), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
        assert_eq!(received, super::super::codec::encode_grpc_message(b"hello").to_vec());

        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn recv_high_watermark_stays_latched_until_low_watermark() {
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
                            transport.read_remaining = STREAM_BUFFER_LOW_WATERMARK + 2;
                            transport
                                .read_pending
                                .resize(STREAM_BUFFER_LOW_WATERMARK + 2, 0xAB);
                            transport.recv_high_watermark_triggered = true;

                            let result = timeout(Duration::from_secs(3), async {
                                let mut probe = [0u8; 1];
                                let first = transport.read(&mut probe).await?;
                                if first != 1
                                    || !transport.recv_high_watermark_triggered
                                    || transport.read_disable_count != 0
                                {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "recv high watermark cleared too early",
                                    ));
                                }

                                let second = transport.read(&mut probe).await?;
                                if second != 1
                                    || transport.recv_high_watermark_triggered
                                    || transport.read_disable_count != 0
                                {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "recv high watermark did not clear at low watermark",
                                    ));
                                }

                                Ok::<(), io::Error>(())
                            })
                            .await
                            .map_err(|_| "server timeout".to_string())
                            .and_then(|r| r.map_err(|e| format!("server error: {e}")));
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
    async fn send_high_watermark_backpressures_write() {
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
                            transport
                                .pending_send_buffer
                                .resize(STREAM_BUFFER_HIGH_WATERMARK, 0);
                            transport.send_high_watermark_triggered = true;
                            let result = timeout(Duration::from_millis(300), transport.write_all(b"hello"))
                                .await
                                .map(|_| Err("write_all completed without backpressure".to_string()))
                                .unwrap_or_else(|_| Ok(()));
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
                            let result = match timeout(Duration::from_secs(12), async {
                                for _ in 0..iterations {
                                    transport.write_all(&payload).await?;
                                }
                                Ok::<(), io::Error>(())
                            })
                            .await
                            {
                                Err(_) => Err("burst write_all timeout".to_string()),
                                Ok(Err(e)) => Err(format!("unexpected burst write error: {e}")),
                                Ok(Ok(())) => match timeout(Duration::from_secs(12), async {
                                    transport.flush().await?;
                                    Ok::<(), io::Error>(())
                                })
                                .await
                                {
                                    Err(_) => Err("burst flush timeout".to_string()),
                                    Ok(Err(e)) => Err(format!("unexpected burst flush error: {e}")),
                                    Ok(Ok(())) => Ok(()),
                                },
                            };
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

        let result = timeout(Duration::from_secs(25), done_rx)
            .await
            .expect("done signal timeout")
            .expect("done channel closed");
        assert!(result.is_ok(), "{}", result.err().unwrap_or_default());

        body_drain_task.abort();
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn send_high_watermark_stays_latched_until_low_watermark() {
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
                            transport
                                .pending_send_buffer
                                .resize(STREAM_BUFFER_HIGH_WATERMARK - 1, 0);
                            transport.send_high_watermark_triggered = true;
                            let result = timeout(Duration::from_secs(1), transport.write(b"hello"))
                                .await
                                .map(|_| Err("write completed without waiting for capacity".to_string()))
                                .unwrap_or_else(|_| Ok(()));
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
