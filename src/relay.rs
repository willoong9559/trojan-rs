use bytes::{Buf, BytesMut};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;

const RELAY_BUFFER_SIZE: usize = 32 * 1024;
pub(crate) const NETWORK_BUFFER_HIGH_WATERMARK: usize = 1024 * 1024;
pub(crate) const NETWORK_BUFFER_LOW_WATERMARK: usize = NETWORK_BUFFER_HIGH_WATERMARK / 2;

pub(crate) trait RelayIo: AsyncRead + AsyncWrite + Unpin {
    fn read_disable(&mut self, _disable: bool) {}

    fn is_write_backpressured(&self) -> bool {
        false
    }
}

impl RelayIo for TcpStream {}

impl RelayIo for tokio::io::DuplexStream {}

impl<S> RelayIo for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
}

#[derive(Default)]
pub(crate) struct WriteBufferWaker {
    waker: Mutex<Option<std::task::Waker>>,
}

impl WriteBufferWaker {
    pub(crate) fn register(&self, waker: &std::task::Waker) {
        let mut slot = self.waker.lock().expect("write buffer waker mutex poisoned");
        match slot.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }

    pub(crate) fn wake(&self) {
        if let Some(waker) = self
            .waker
            .lock()
            .expect("write buffer waker mutex poisoned")
            .take()
        {
            waker.wake();
        }
    }
}

struct WriteBufferWatermarkInner {
    buffered_bytes: usize,
    high_watermark_triggered: bool,
    wakers: Vec<Weak<WriteBufferWaker>>,
}

pub(crate) struct WriteBufferWatermark {
    inner: Mutex<WriteBufferWatermarkInner>,
    high_watermark: usize,
    low_watermark: usize,
}

impl WriteBufferWatermark {
    pub(crate) fn new(high_watermark: usize, low_watermark: usize) -> Self {
        Self {
            inner: Mutex::new(WriteBufferWatermarkInner {
                buffered_bytes: 0,
                high_watermark_triggered: false,
                wakers: Vec::new(),
            }),
            high_watermark,
            low_watermark,
        }
    }

    pub(crate) fn register_waker(&self, write_waker: &Arc<WriteBufferWaker>) {
        self.inner
            .lock()
            .expect("write buffer watermark mutex poisoned")
            .wakers
            .push(Arc::downgrade(write_waker));
    }

    pub(crate) fn is_backpressured(&self) -> bool {
        self.inner
            .lock()
            .expect("write buffer watermark mutex poisoned")
            .high_watermark_triggered
    }

    pub(crate) fn update_buffered_bytes(&self, previous: usize, current: usize) {
        let mut wake_writers = Vec::new();

        {
            let mut inner = self
                .inner
                .lock()
                .expect("write buffer watermark mutex poisoned");
            if current >= previous {
                inner.buffered_bytes = inner
                    .buffered_bytes
                    .saturating_add(current - previous);
            } else {
                inner.buffered_bytes = inner
                    .buffered_bytes
                    .saturating_sub(previous - current);
            }

            let next_high_watermark_triggered = if inner.high_watermark_triggered {
                inner.buffered_bytes > self.low_watermark
            } else {
                inner.buffered_bytes >= self.high_watermark
            };

            if next_high_watermark_triggered != inner.high_watermark_triggered {
                inner.high_watermark_triggered = next_high_watermark_triggered;
                inner.wakers.retain(|weak| {
                    if let Some(write_waker) = weak.upgrade() {
                        wake_writers.push(write_waker);
                        true
                    } else {
                        false
                    }
                });
            }
        }

        for write_waker in wake_writers {
            write_waker.wake();
        }
    }
}

pub(crate) struct NetworkBufferedIo<S> {
    inner: S,
    pending_write_buffer: BytesMut,
    accounted_write_bytes: usize,
    write_buffer_watermark: Arc<WriteBufferWatermark>,
    write_waker: Arc<WriteBufferWaker>,
    read_disable_count: usize,
    read_waker: Option<std::task::Waker>,
    write_closed: bool,
}

impl<S> NetworkBufferedIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(inner: S) -> Self {
        Self::with_write_buffer_watermark(
            inner,
            Arc::new(WriteBufferWatermark::new(
                NETWORK_BUFFER_HIGH_WATERMARK,
                NETWORK_BUFFER_LOW_WATERMARK,
            )),
        )
    }

    pub(crate) fn with_write_buffer_watermark(
        inner: S,
        write_buffer_watermark: Arc<WriteBufferWatermark>,
    ) -> Self {
        let write_waker = Arc::new(WriteBufferWaker::default());
        write_buffer_watermark.register_waker(&write_waker);
        Self {
            inner,
            pending_write_buffer: BytesMut::new(),
            accounted_write_bytes: 0,
            write_buffer_watermark,
            write_waker,
            read_disable_count: 0,
            read_waker: None,
            write_closed: false,
        }
    }

    fn replace_read_waker(&mut self, waker: &std::task::Waker) {
        match self.read_waker.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => self.read_waker = Some(waker.clone()),
        }
    }

    fn wake_read_task(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn sync_write_buffer_accounting(&mut self) {
        let current = self.pending_write_buffer.len();
        if current == self.accounted_write_bytes {
            return;
        }
        self.write_buffer_watermark
            .update_buffered_bytes(self.accounted_write_bytes, current);
        self.accounted_write_bytes = current;
    }

    fn enqueue_pending_bytes(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        self.pending_write_buffer.extend_from_slice(buf);
        self.sync_write_buffer_accounting();
    }

    fn poll_flush_pending_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pending_write_buffer.is_empty() {
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inner).poll_write(cx, self.pending_write_buffer.chunk()) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "network write returned zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_write_buffer.advance(n);
                    self.sync_write_buffer_accounting();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncRead for NetworkBufferedIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_disable_count > 0 {
            self.replace_read_waker(cx.waker());
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for NetworkBufferedIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network transport closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        self.write_waker.register(cx.waker());

        match self.poll_flush_pending_write_buffer(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                if self.write_buffer_watermark.is_backpressured() {
                    return Poll::Pending;
                }
            }
        }

        if !self.pending_write_buffer.is_empty() {
            self.enqueue_pending_bytes(buf);
            return Poll::Ready(Ok(buf.len()));
        }

        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "network write returned zero bytes",
            ))),
            Poll::Ready(Ok(n)) => {
                self.enqueue_pending_bytes(&buf[n..]);
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.enqueue_pending_bytes(buf);
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.write_waker.register(cx.waker());
        match self.poll_flush_pending_write_buffer(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.write_closed = true;
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<S> RelayIo for NetworkBufferedIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn read_disable(&mut self, disable: bool) {
        if disable {
            self.read_disable_count = self.read_disable_count.saturating_add(1);
            return;
        }

        if self.read_disable_count == 0 {
            return;
        }

        self.read_disable_count -= 1;
        if self.read_disable_count == 0 {
            self.wake_read_task();
        }
    }

    fn is_write_backpressured(&self) -> bool {
        self.write_buffer_watermark.is_backpressured()
    }
}

impl<S> Drop for NetworkBufferedIo<S> {
    fn drop(&mut self) {
        self.write_buffer_watermark
            .update_buffered_bytes(self.accounted_write_bytes, 0);
        self.accounted_write_bytes = 0;
    }
}

struct DirectionState {
    pending: BytesMut,
    read_eof: bool,
    write_shutdown: bool,
    src_read_disabled: bool,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            pending: BytesMut::with_capacity(RELAY_BUFFER_SIZE),
            read_eof: false,
            write_shutdown: false,
            src_read_disabled: false,
        }
    }

    fn set_src_read_disabled<S>(&mut self, src: &mut S, disable: bool)
    where
        S: RelayIo,
    {
        if self.src_read_disabled == disable {
            return;
        }
        src.read_disable(disable);
        self.src_read_disabled = disable;
    }
}

fn mark_activity(activity_sequence: &AtomicU64, activity_tx: &watch::Sender<u64>) {
    let next = activity_sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let _ = activity_tx.send_replace(next);
}

fn poll_direction<SRC, DST>(
    src: &mut SRC,
    dst: &mut DST,
    state: &mut DirectionState,
    cx: &mut Context<'_>,
    activity_sequence: &AtomicU64,
    activity_tx: &watch::Sender<u64>,
) -> Poll<io::Result<()>>
where
    SRC: RelayIo,
    DST: RelayIo,
{
    loop {
        if !state.pending.is_empty() {
            match Pin::new(&mut *dst).poll_write(cx, state.pending.chunk()) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "relay write returned zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    state.pending.advance(n);
                    mark_activity(activity_sequence, activity_tx);
                    if state.pending.is_empty() && !dst.is_write_backpressured() {
                        state.set_src_read_disabled(src, false);
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if dst.is_write_backpressured() {
                        state.set_src_read_disabled(src, true);
                    }
                    return Poll::Pending;
                }
            }
        }

        if dst.is_write_backpressured() {
            state.set_src_read_disabled(src, true);
            match Pin::new(&mut *dst).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    if !dst.is_write_backpressured() {
                        state.set_src_read_disabled(src, false);
                    }
                    continue;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if state.read_eof {
            if !state.write_shutdown {
                match Pin::new(&mut *dst).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        state.write_shutdown = true;
                        state.set_src_read_disabled(src, false);
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            state.set_src_read_disabled(src, false);
            return Poll::Ready(Ok(()));
        }

        let mut buf = [0u8; RELAY_BUFFER_SIZE];
        let mut read_buf = ReadBuf::new(&mut buf);
        match Pin::new(&mut *src).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    state.read_eof = true;
                    continue;
                }
                state.pending.extend_from_slice(filled);
                mark_activity(activity_sequence, activity_tx);
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
    }
}

fn poll_copy_bidirectional<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b: &mut DirectionState,
    b_to_a: &mut DirectionState,
    cx: &mut Context<'_>,
    activity_sequence: &AtomicU64,
    activity_tx: &watch::Sender<u64>,
) -> Poll<io::Result<()>>
where
    A: RelayIo,
    B: RelayIo,
{
    let mut a_done = false;
    let mut b_done = false;

    match poll_direction(a, b, a_to_b, cx, activity_sequence, activity_tx) {
        Poll::Ready(Ok(())) => a_done = true,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Pending => {}
    }

    match poll_direction(b, a, b_to_a, cx, activity_sequence, activity_tx) {
        Poll::Ready(Ok(())) => b_done = true,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Pending => {}
    }

    if a_done && b_done {
        Poll::Ready(Ok(()))
    } else {
        Poll::Pending
    }
}

/// 双向转发，支持空闲超时检测，并显式传播读停用背压。
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    mut a: A,
    mut b: B,
    idle_timeout_secs: u64,
) -> io::Result<bool>
where
    A: RelayIo,
    B: RelayIo,
{
    let idle_timeout = tokio::time::Duration::from_secs(idle_timeout_secs);
    let activity_sequence = AtomicU64::new(0);
    let (activity_tx, mut activity_rx) = watch::channel(0u64);

    let mut a_to_b = DirectionState::new();
    let mut b_to_a = DirectionState::new();
    let copy_task = poll_fn(|cx| {
        poll_copy_bidirectional(
            &mut a,
            &mut b,
            &mut a_to_b,
            &mut b_to_a,
            cx,
            &activity_sequence,
            &activity_tx,
        )
    });

    let timeout_check = async {
        let sleep = tokio::time::sleep(idle_timeout);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                _ = &mut sleep => {
                    return;
                }
                changed = activity_rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + idle_timeout);
                }
            }
        }
    };

    tokio::select! {
        result = copy_task => {
            result?;
            Ok(true)
        }
        _ = timeout_check => {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::task::noop_waker_ref;
    use std::collections::VecDeque;
    use std::task::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;
    use tokio::time::{timeout, Duration};

    #[derive(Default)]
    struct MockRelayIo {
        read_chunks: VecDeque<Vec<u8>>,
        written: Vec<u8>,
        read_disable_events: Vec<bool>,
        backpressured: bool,
        write_blocks_once: bool,
        write_pending_once: bool,
        shutdown: bool,
    }

    impl MockRelayIo {
        fn with_read_chunks(chunks: &[&[u8]]) -> Self {
            Self {
                read_chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                ..Self::default()
            }
        }
    }

    impl AsyncRead for MockRelayIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.read_chunks.pop_front() {
                let to_copy = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..to_copy]);
                if to_copy < chunk.len() {
                    self.read_chunks.push_front(chunk[to_copy..].to_vec());
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockRelayIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_pending_once {
                self.write_pending_once = false;
                return Poll::Pending;
            }

            if self.write_blocks_once {
                self.write_blocks_once = false;
                self.backpressured = true;
                return Poll::Pending;
            }

            if self.backpressured {
                return Poll::Pending;
            }

            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if self.backpressured {
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    impl RelayIo for MockRelayIo {
        fn read_disable(&mut self, disable: bool) {
            self.read_disable_events.push(disable);
        }

        fn is_write_backpressured(&self) -> bool {
            self.backpressured
        }
    }

    #[tokio::test]
    async fn custom_pump_relays_in_both_directions() {
        let (mut client, relay_client) = tokio::io::duplex(64 * 1024);
        let (relay_server, mut server) = tokio::io::duplex(64 * 1024);

        let relay_task = tokio::spawn(async move {
            copy_bidirectional_with_idle_timeout(relay_client, relay_server, 30).await
        });

        client.write_all(b"hello").await.expect("client write should succeed");
        let mut server_buf = [0u8; 5];
        server
            .read_exact(&mut server_buf)
            .await
            .expect("server read should succeed");
        assert_eq!(&server_buf, b"hello");

        server.write_all(b"world").await.expect("server write should succeed");
        let mut client_buf = [0u8; 5];
        client
            .read_exact(&mut client_buf)
            .await
            .expect("client read should succeed");
        assert_eq!(&client_buf, b"world");

        client.shutdown().await.expect("client shutdown should succeed");
        server.shutdown().await.expect("server shutdown should succeed");

        let relay_result = timeout(Duration::from_secs(3), relay_task)
            .await
            .expect("relay task timeout")
            .expect("relay task panicked")
            .expect("relay should complete successfully");
        assert!(relay_result);
    }

    #[tokio::test]
    async fn idle_timeout_expires_promptly_without_activity() {
        let (client, server) = tokio::io::duplex(64 * 1024);

        let result = timeout(
            Duration::from_secs(2),
            copy_bidirectional_with_idle_timeout(client, server, 1),
        )
        .await
        .expect("idle timeout should not be delayed by coarse polling")
        .expect("relay future should complete");

        assert!(!result);
    }

    #[test]
    fn network_buffered_io_backpressure_tracks_actual_socket_queue() {
        let inner = MockRelayIo {
            write_blocks_once: true,
            ..MockRelayIo::default()
        };
        let watermark = std::sync::Arc::new(WriteBufferWatermark::new(4, 2));
        let mut io = NetworkBufferedIo::with_write_buffer_watermark(inner, watermark.clone());
        let mut cx = Context::from_waker(noop_waker_ref());

        let first = Pin::new(&mut io).poll_write(&mut cx, b"hello");
        assert!(matches!(first, Poll::Ready(Ok(5))));
        assert!(watermark.is_backpressured());
        assert!(io.is_write_backpressured());

        let second = Pin::new(&mut io).poll_write(&mut cx, b"!");
        assert!(matches!(second, Poll::Pending));

        io.inner.backpressured = false;
        let flushed = Pin::new(&mut io).poll_flush(&mut cx);
        assert!(matches!(flushed, Poll::Ready(Ok(()))));
        assert!(!watermark.is_backpressured());
        assert_eq!(io.inner.written, b"hello");
    }

    #[test]
    fn poll_direction_toggles_read_disable_with_backpressure() {
        let mut src = MockRelayIo::with_read_chunks(&[b"hello"]);
        let mut dst = MockRelayIo {
            write_blocks_once: true,
            ..MockRelayIo::default()
        };
        let mut state = DirectionState::new();
        let activity_sequence = AtomicU64::new(0);
        let (activity_tx, _activity_rx) = watch::channel(0u64);
        let mut cx = Context::from_waker(noop_waker_ref());

        let first = poll_direction(
            &mut src,
            &mut dst,
            &mut state,
            &mut cx,
            &activity_sequence,
            &activity_tx,
        );
        assert!(matches!(first, Poll::Pending));
        assert_eq!(src.read_disable_events, vec![true]);
        assert_eq!(state.pending.as_ref(), b"hello");

        let second = poll_direction(
            &mut src,
            &mut dst,
            &mut state,
            &mut cx,
            &activity_sequence,
            &activity_tx,
        );
        assert!(matches!(second, Poll::Pending));
        assert_eq!(src.read_disable_events, vec![true]);

        dst.backpressured = false;
        let third = poll_direction(
            &mut src,
            &mut dst,
            &mut state,
            &mut cx,
            &activity_sequence,
            &activity_tx,
        );
        assert!(matches!(third, Poll::Ready(Ok(()))));
        assert_eq!(src.read_disable_events, vec![true, false]);
        assert_eq!(dst.written, b"hello");
        assert!(dst.shutdown);
    }

    #[test]
    fn poll_direction_pending_without_backpressure_does_not_toggle_read_disable() {
        let mut src = MockRelayIo::with_read_chunks(&[b"hello"]);
        let mut dst = MockRelayIo {
            write_pending_once: true,
            ..MockRelayIo::default()
        };
        let mut state = DirectionState::new();
        let activity_sequence = AtomicU64::new(0);
        let (activity_tx, _activity_rx) = watch::channel(0u64);
        let mut cx = Context::from_waker(noop_waker_ref());

        let first = poll_direction(
            &mut src,
            &mut dst,
            &mut state,
            &mut cx,
            &activity_sequence,
            &activity_tx,
        );
        assert!(matches!(first, Poll::Pending));
        assert!(src.read_disable_events.is_empty());
        assert_eq!(state.pending.as_ref(), b"hello");

        let second = poll_direction(
            &mut src,
            &mut dst,
            &mut state,
            &mut cx,
            &activity_sequence,
            &activity_tx,
        );
        assert!(matches!(second, Poll::Ready(Ok(()))));
        assert!(src.read_disable_events.is_empty());
        assert_eq!(dst.written, b"hello");
        assert!(dst.shutdown);
    }
}
