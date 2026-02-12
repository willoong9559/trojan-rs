use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use pin_project_lite::pin_project;

pin_project! {
    struct TimedStream<S> {
        #[pin]
        inner: S,
        start_time: Instant,
        last_activity: Arc<AtomicU64>,
    }
}

impl<S> TimedStream<S> {
    fn new(inner: S, start_time: Instant, last_activity: Arc<AtomicU64>) -> Self {
        Self { inner, start_time, last_activity }
    }
}

impl<S: AsyncRead> AsyncRead for TimedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let result = this.inner.poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Ok(())) if !buf.filled().is_empty()) {
            this.last_activity.store(this.start_time.elapsed().as_secs(), Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite> AsyncWrite for TimedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let result = this.inner.poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Ok(n)) if *n > 0) {
            this.last_activity.store(this.start_time.elapsed().as_secs(), Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// 双向转发，支持空闲超时检测
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout_secs: u64,
) -> std::io::Result<bool>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let start_time = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));

    let mut stream_a = TimedStream::new(a, start_time, Arc::clone(&last_activity));
    let mut stream_b = TimedStream::new(b, start_time, Arc::clone(&last_activity));

    let copy_task = tokio::io::copy_bidirectional(&mut stream_a, &mut stream_b);

    let timeout_check = async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            let last_active = last_activity.load(Ordering::Relaxed);
            let current_elapsed = start_time.elapsed().as_secs();
            let idle_secs = current_elapsed.saturating_sub(last_active);
            if idle_secs >= idle_timeout_secs {
                return idle_secs;
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
