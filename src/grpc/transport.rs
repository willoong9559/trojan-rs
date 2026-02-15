use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{Buf, Bytes, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use h2::{Reason, RecvStream, SendStream};

use super::codec::{encode_grpc_message, parse_grpc_message};
use super::{GRPC_MAX_MESSAGE_SIZE, MAX_FRAME_SIZE, READ_BUFFER_SIZE};

/// gRPC 传输层（兼容 v2ray）
///
/// 实现 AsyncRead + AsyncWrite，可以像普通 TCP 流一样使用
pub struct GrpcH2cTransport {
    pub(crate) recv_stream: RecvStream,
    pub(crate) send_stream: SendStream<Bytes>,
    pub(crate) read_pending: BytesMut,
    pub(crate) read_buf: Bytes,
    pub(crate) read_pos: usize,
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
        buf.put_slice(&remaining[..to_copy]);
        self.read_pos += to_copy;

        if self.read_pos >= self.read_buf.len() {
            self.read_buf = Bytes::new();
            self.read_pos = 0;
        }

        true
    }

    fn parse_pending_message(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<Option<()>> {
        match parse_grpc_message(&self.read_pending)? {
            Some((consumed, payload)) => {
                let to_copy = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..to_copy]);

                if to_copy < payload.len() {
                    self.read_buf = Bytes::copy_from_slice(&payload[to_copy..]);
                    self.read_pos = 0;
                }

                self.read_pending.advance(consumed);
                let _ = self.recv_stream.flow_control().release_capacity(consumed);
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

    fn poll_send_frame(&mut self, cx: &mut Context<'_>, frame: Bytes) -> Poll<io::Result<()>> {
        let needed = frame.len();

        loop {
            let capacity = self.send_stream.capacity();
            if capacity < needed {
                self.send_stream.reserve_capacity(needed.min(MAX_FRAME_SIZE as usize));
                match self.send_stream.poll_capacity(cx) {
                    Poll::Ready(Some(Ok(cap))) if cap >= needed => continue,
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

            return match self.send_stream.send_data(frame.clone(), false) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("gRPC send error: {}", e),
                ))),
            };
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
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
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

        // Frame strategy: each gRPC frame carries at most 32KiB payload.
        let to_write = Self::frame_payload_len(buf.len());
        let frame = encode_grpc_message(&buf[..to_write]).freeze();

        match self.poll_send_frame(cx, frame) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(to_write)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;

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
