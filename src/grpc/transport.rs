use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf, Bytes};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use std::collections::VecDeque;
use h2::{SendStream, RecvStream, Reason};
use tracing::warn;

use super::codec::{parse_grpc_message, encode_grpc_message};
use super::{MAX_FRAME_SIZE, GRPC_MAX_MESSAGE_SIZE, MAX_SEND_QUEUE_BYTES, READ_BUFFER_SIZE};

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
    pub(crate) send_queue: VecDeque<Bytes>,
    pub(crate) send_queue_bytes: usize,
    pub(crate) current_frame: Option<Bytes>,
    pub(crate) current_frame_offset: usize,
    pub(crate) closed: bool,
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
            send_queue: VecDeque::new(),
            send_queue_bytes: 0,
            current_frame: None,
            current_frame_offset: 0,
            closed: false,
        }
    }

    fn poll_send_queued(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref frame) = self.current_frame {
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

        loop {
            let remaining = frame.len() - self.current_frame_offset;
            if remaining == 0 {
                return Poll::Ready(Ok(()));
            }

            let capacity = self.send_stream.capacity();
            if capacity == 0 {
                self.send_stream.reserve_capacity(remaining.min(MAX_FRAME_SIZE as usize));
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap > 0 => continue,
                    Poll::Ready(Some(Ok(_))) => return Poll::Pending,
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
                    Poll::Pending => return Poll::Pending,
                }
            }

            let send_size = remaining.min(capacity);
            let chunk = frame.slice(self.current_frame_offset..self.current_frame_offset + send_size);
            
            match self.send_stream.send_data(chunk, false) {
                Ok(()) => {
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
        self.send_stream.reserve_capacity(MAX_FRAME_SIZE as usize);
        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(cap))) if cap > 0 => Poll::Ready(Ok(())),
            Poll::Ready(Some(Ok(_))) => Poll::Pending,
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("gRPC capacity error: {}", e),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
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

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.pending_release_capacity > 0 {
                let to_release = self.pending_release_capacity.min(to_copy);
                if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release) {
                    warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
                }
                self.pending_release_capacity -= to_release;
            }

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
                    buf.put_slice(&payload[..to_copy]);
                    
                    if to_copy < payload.len() {
                        self.read_buf = Bytes::copy_from_slice(&payload[to_copy..]);
                        self.read_pos = 0;
                    }
                    
                    self.read_pending.advance(consumed);
                    
                    let to_release = self.pending_release_capacity.min(consumed);
                    if to_release > 0 {
                        if let Err(e) = self.recv_stream.flow_control().release_capacity(to_release) {
                            warn!(error = %e, to_release, "Failed to release HTTP/2 flow control capacity");
                        }
                        self.pending_release_capacity -= to_release;
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let chunk_len = chunk.len();
                    self.read_pending.extend_from_slice(&chunk);
                    self.pending_release_capacity += chunk_len;
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
                "transport closed"
            )));
        }

        match self.poll_send_queued(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        if self.send_queue_bytes >= MAX_SEND_QUEUE_BYTES {
            return match self.poll_wait_send_capacity(cx) {
                Poll::Ready(Ok(())) => {
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }

        let to_write = buf.len().min(GRPC_MAX_MESSAGE_SIZE);
        let frame = encode_grpc_message(&buf[..to_write]);
        let frame_bytes = frame.len();
        self.send_queue.push_back(frame.freeze());
        self.send_queue_bytes += frame_bytes;

        match self.poll_send_queued(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
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
                
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                match self.send_stream.send_trailers(trailers) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(e) => {
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
