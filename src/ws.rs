use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, tungstenite::Message};
use futures_util::StreamExt;
use bytes::Bytes;
use std::pin::Pin;
use std::task::{Context, Poll};


/// WebSocket 传输层
pub struct WebSocketTransport {
    ws_read: Pin<Box<dyn futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Send>>,
    ws_write: Pin<Box<dyn futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send>>,
    read_buffer: Bytes,  // 使用 Bytes 引用计数，避免复制
    read_pos: usize,
    write_pending: Option<Bytes>,  // 使用 Bytes 引用计数，避免复制
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
            read_buffer: Bytes::new(),
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
                self.read_buffer = Bytes::new();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // 从 WebSocket 流直接读取（使用 Bytes 引用计数）
        loop {
            match self.ws_read.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    // 将 Vec<u8> 转换为 Bytes（引用计数共享，避免复制）
                    let data_bytes = Bytes::from(data);
                    let to_copy = data_bytes.len().min(buf.remaining());
                    buf.put_slice(&data_bytes[..to_copy]);

                    if to_copy < data_bytes.len() {
                        // 保存剩余数据（使用 Bytes 引用计数，不复制）
                        self.read_buffer = data_bytes;
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
                    // Message::Binary 需要 Vec<u8>，但 pending 是 Bytes
                    // 如果只有一个引用，to_vec() 可以避免复制（通过 into()）
                    match self.ws_write.as_mut().start_send(Message::Binary(pending.to_vec())) {
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

        // 直接发送到 WebSocket（使用 Bytes 引用计数，避免复制）
        match self.ws_write.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                // 使用 Bytes::copy_from_slice 创建 Bytes，然后转换为 Vec（Message::Binary 需要 Vec<u8>）
                // 注意：这里仍然需要一次复制，因为 Message::Binary 要求 Vec<u8>
                let data = Bytes::copy_from_slice(buf);
                match self.ws_write.as_mut().start_send(Message::Binary(data.to_vec())) {
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
                // 保存数据等待下次重试（使用 Bytes 引用计数）
                self.write_pending = Some(Bytes::copy_from_slice(buf));
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
