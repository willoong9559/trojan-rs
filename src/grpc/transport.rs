use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use h2::{Reason, RecvStream, SendStream};

use super::codec::{encode_grpc_message, parse_grpc_message};
use super::{GRPC_MAX_MESSAGE_SIZE, READ_BUFFER_SIZE, STREAM_WRITE_TIMEOUT_SECS};

/// gRPC 传输层（兼容 v2ray）
///
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) send_stream: SendStream<Bytes>,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_buf: Bytes,
    pub(crate) read_pos: usize,
    pub(crate) pending_release_capacity: usize,
    pub(crate) pending_frame: Option<Bytes>,
    pub(crate) pending_frame_offset: usize,
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
            read_buf: Bytes::new(),
            read_pos: 0,
            pending_release_capacity: 0,
            pending_frame: None,
            pending_frame_offset: 0,
            write_wait_timeout: None,
            closed: false,
            trailers_sent: false,
        }
    }

    fn copy_from_read_buffer(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_pos >= self.read_buf.len() {
            return false;
        }

        let remaining = &self.read_buf[self.read_pos..];
        let to_copy = remaining.len().min(buf.remaining());
        if to_copy == 0 {
            return false;
        }

        buf.put_slice(&remaining[..to_copy]);
        self.read_pos += to_copy;
        self.release_recv_capacity(to_copy);

        if self.read_pos >= self.read_buf.len() {
            self.read_buf = Bytes::new();
            self.read_pos = 0;
        }

        true
    }

    fn parse_pending_message(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<Option<()>> {
        match parse_grpc_message(&self.read_pending)? {
            Some((consumed, payload)) => {
                let payload_len = payload.len();
                let to_copy = payload_len.min(buf.remaining());
                buf.put_slice(&payload[..to_copy]);

                if to_copy < payload_len {
                    let payload_start = consumed - payload_len;
                    let frame = self.read_pending.split_to(consumed).freeze();
                    self.read_buf = frame.slice(payload_start + to_copy..consumed);
                    self.read_pos = 0;
                } else {
                    let _ = self.read_pending.split_to(consumed);
                }

                let frame_overhead = consumed.saturating_sub(payload_len);
                self.release_recv_capacity(frame_overhead + to_copy);
                Ok(Some(()))
            }
            None => Ok(None),
        }
    }

    fn poll_recv_next_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        match self.recv_stream.poll_data(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = chunk.len();
                if self.read_pending.len() + chunk_len > READ_BUFFER_SIZE {
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
                    return Poll::Ready(Ok(false));
                }
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("gRPC recv error: {}", e),
                )))
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(false))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_pending_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_frame.is_none() {
            return Poll::Ready(Ok(()));
        }

        loop {
            let frame_len = self.pending_frame.as_ref().expect("checked above").len();
            if self.pending_frame_offset >= frame_len {
                self.pending_frame = None;
                self.pending_frame_offset = 0;
                return Poll::Ready(Ok(()));
            }

            let remaining = frame_len - self.pending_frame_offset;
            let capacity = self.send_stream.capacity();
            if capacity == 0 {
                if self.write_wait_timeout.is_none() {
                    self.write_wait_timeout = Some(Box::pin(tokio::time::sleep(Duration::from_secs(
                        STREAM_WRITE_TIMEOUT_SECS,
                    ))));
                }
                self.send_stream.reserve_capacity(remaining);
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => {
                        self.write_wait_timeout = None;
                        continue;
                    }
                    Poll::Ready(Some(Ok(_))) => {
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
                    Poll::Pending => {
                        if self.write_wait_timed_out(cx) {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "gRPC stream write stalled waiting for flow-control capacity",
                            )));
                        }
                        return Poll::Pending;
                    }
                }
            }

            let send_size = remaining.min(capacity);
            let chunk = {
                let frame = self.pending_frame.as_ref().expect("checked above");
                frame.slice(self.pending_frame_offset..self.pending_frame_offset + send_size)
            };

            match self.send_stream.send_data(chunk, false) {
                Ok(()) => {
                    self.write_wait_timeout = None;
                    self.pending_frame_offset += send_size;
                    if self.pending_frame_offset >= frame_len {
                        self.pending_frame = None;
                        self.pending_frame_offset = 0;
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

    fn write_wait_timed_out(&mut self, cx: &mut Context<'_>) -> bool {
        if let Some(timeout) = &mut self.write_wait_timeout {
            return timeout.as_mut().poll(cx).is_ready();
        }
        false
    }

    fn release_recv_capacity(&mut self, max_release: usize) {
        if self.pending_release_capacity == 0 {
            return;
        }
        let to_release = self.pending_release_capacity.min(max_release);
        if to_release == 0 {
            return;
        }
        if self.recv_stream.flow_control().release_capacity(to_release).is_ok() {
            self.pending_release_capacity -= to_release;
        }
    }

    #[inline]
    fn frame_payload_len(total: usize) -> usize {
        total.min(GRPC_MAX_MESSAGE_SIZE)
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

        if self.copy_from_read_buffer(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.parse_pending_message(buf) {
                Ok(Some(())) => return Poll::Ready(Ok(())),
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            match self.poll_recv_next_chunk(cx) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => {
                    if !self.read_pending.is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "gRPC stream closed with incomplete message",
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
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
                "transport closed",
            )));
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match self.poll_send_pending_frame(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Frame strategy: each gRPC message carries at most 64KiB payload.
        // HTTP/2 frame splitting is handled by the h2 layer.
        let to_write = Self::frame_payload_len(buf.len());
        self.pending_frame = Some(encode_grpc_message(&buf[..to_write]).freeze());
        self.pending_frame_offset = 0;

        match self.poll_send_pending_frame(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(to_write)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(to_write)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_send_pending_frame(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
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
}
