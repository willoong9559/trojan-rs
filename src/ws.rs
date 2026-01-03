use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, tungstenite::Message};
use futures_util::{Stream, Sink};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use bytes::Bytes;

pub struct WebSocketTransport<S> {
    ws_stream: Pin<Box<TungsteniteStream<S>>>,
    read_buffer: Bytes,
    read_pos: usize,
    write_buffer: Vec<u8>,  // 保持 Vec<u8>， WebSocket 库需要
    write_pending: bool,
    closed: bool,
}

impl<S> WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(ws_stream: TungsteniteStream<S>) -> Self {
        Self {
            ws_stream: Box::pin(ws_stream),
            read_buffer: Bytes::new(),
            read_pos: 0,
            write_buffer: Vec::new(),
            write_pending: false,
            closed: false,
        }
    }
}

impl<S> AsyncRead for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        // 如果缓冲区还有数据，先消费缓冲区
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer = Bytes::new();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // 直接从 WebSocket 流读取
        match Stream::poll_next(self.ws_stream.as_mut(), cx) {
            Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.read_buffer = Bytes::copy_from_slice(&data[to_copy..]);
                    self.read_pos = 0;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(Message::Close(_))) | Some(Err(_))) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // 非二进制消息，跳过
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WebSocket closed",
            )));
        }

        // 如果有待发送的数据，先尝试发送
        if self.write_pending {
            match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    // 发送缓冲区中的数据
                    let data = std::mem::take(&mut self.write_buffer);
                    match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data)) {
                        Ok(()) => {
                            self.write_pending = false;
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("WebSocket send error: {}", e),
                            )));
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("WebSocket error: {}", e),
                    )));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        // 将新数据添加到缓冲区
        self.write_buffer.extend_from_slice(buf);
        
        // 尝试立即发送
        match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
            Poll::Ready(Ok(())) => {
                let data = std::mem::take(&mut self.write_buffer);
                match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data)) {
                    Ok(()) => {
                        Poll::Ready(Ok(buf.len()))
                    }
                    Err(e) => {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("WebSocket send error: {}", e),
                        )))
                    }
                }
            }
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("WebSocket error: {}", e),
                )))
            }
            Poll::Pending => {
                self.write_pending = true;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // 确保所有待发送的数据都已发送
        if self.write_pending {
            match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    if !self.write_buffer.is_empty() {
                        let data = std::mem::take(&mut self.write_buffer);
                        match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data)) {
                            Ok(()) => {
                                self.write_pending = false;
                            }
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    format!("WebSocket send error: {}", e),
                                )));
                            }
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("WebSocket error: {}", e),
                    )));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        Sink::poll_flush(self.ws_stream.as_mut(), cx)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("WebSocket flush error: {}", e)))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.closed = true;
        // 刷新所有待发送的数据
        // WebSocket 连接的关闭由底层流处理，这里只需要确保数据已刷新
        self.as_mut().poll_flush(cx)
    }
}
