use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};

pub struct WebSocketTransport {
    read_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl WebSocketTransport {
    pub fn new<S>(ws_stream: TungsteniteStream<S>) -> Self 
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut ws_write, mut ws_read) = ws_stream.split();
        let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();

        // WebSocket 读取任务
        tokio::spawn(async move {
            while let Some(msg) = ws_read.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        if read_tx.send(data).is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                }
            }
        });

        // WebSocket 写入任务
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if ws_write.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            let _ = ws_write.close().await;
        });

        Self {
            read_rx,
            write_tx,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for WebSocketTransport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
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

            return std::task::Poll::Ready(Ok(()));
        }

        // 尝试接收新数据
        match self.read_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.read_buffer = data;
                    self.read_pos = to_copy;
                }

                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // 通道关闭，返回 EOF
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for WebSocketTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.write_tx.send(buf.to_vec()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "WebSocket write channel closed",
            ))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}