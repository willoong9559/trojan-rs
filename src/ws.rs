use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, tungstenite::Message};
use futures_util::StreamExt;
use std::pin::Pin;
use std::task::{Context, Poll};


/// WebSocket 传输层
pub struct WebSocketTransport {
    ws_read: Pin<Box<dyn futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Send>>,
    ws_write: Pin<Box<dyn futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    write_pending: Option<Vec<u8>>,
}

impl WebSocketTransport {
    pub fn new<S>(ws_stream: TungsteniteStream<S>) -> Self 
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 使用 split 分离读写，然后转换为 trait object
        let (ws_write, ws_read) = ws_stream.split();
        
        Self {
            ws_read: Box::pin(ws_read),
            ws_write: Box::pin(ws_write),
            read_buffer: Vec::new(),
            read_pos: 0,
            write_pending: None,
        }
    }
}

impl AsyncRead for WebSocketTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 如果缓冲区还有数据，先消费缓冲区
        if self.read_pos < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // 从 WebSocket 流直接读取（零拷贝）
        loop {
            match self.ws_read.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    let to_copy = data.len().min(buf.remaining());
                    buf.put_slice(&data[..to_copy]);

                    if to_copy < data.len() {
                        self.read_buffer = data;
                        self.read_pos = to_copy;
                    }

                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(Some(Ok(_))) => {
                    // 忽略非二进制消息
                    continue;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WebSocketTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 如果有待发送的数据，先尝试发送
        if let Some(pending) = self.write_pending.take() {
            match self.ws_write.as_mut().poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match self.ws_write.as_mut().start_send(Message::Binary(pending)) {
                        Ok(()) => {
                            // 继续处理新数据
                        }
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("WebSocket send error: {}", e),
                            )));
                        }
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WebSocket error: {}", e),
                    )));
                }
                Poll::Pending => {
                    // 还没准备好，保存数据等待
                    self.write_pending = Some(pending);
                    return Poll::Pending;
                }
            }
        }

        // 直接发送到 WebSocket
        match self.ws_write.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                match self.ws_write.as_mut().start_send(Message::Binary(buf.to_vec())) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("WebSocket send error: {}", e),
                    ))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => {
                // 保存数据等待下次重试
                self.write_pending = Some(buf.to_vec());
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.ws_write.as_mut().poll_flush(cx)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket flush error: {}", e),
            ))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.ws_write.as_mut().poll_close(cx)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WebSocket close error: {}", e),
            ))
    }
}
