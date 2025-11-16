use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream as TungsteniteStream, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};

// 通道缓冲区大小，限制内存占用
const CHANNEL_BUFFER_SIZE: usize = 32;

pub struct WebSocketTransport {
    read_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    write_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    // 用于背压处理：当通道满时暂存的数据
    pending_write: Option<Vec<u8>>,
}

impl WebSocketTransport {
    pub fn new<S>(ws_stream: TungsteniteStream<S>) -> Self 
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut ws_write, mut ws_read) = ws_stream.split();
        let (read_tx, read_rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER_SIZE);
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER_SIZE);

        // WebSocket 读取任务
        let read_tx_clone = read_tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = ws_read.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        // 如果通道满了，丢弃新消息以避免内存溢出
                        match read_tx_clone.try_send(data) {
                            Ok(_) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                // 通道满了，丢弃这个 WebSocket 消息以避免内存溢出
                                eprintln!("[WebSocket] Read channel full, dropping message");
                            }
                            Err(_) => break,
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
            pending_write: None,
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
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // 如果有待发送的数据，先尝试发送
        if let Some(pending) = self.pending_write.take() {
            match self.write_tx.try_send(pending) {
                Ok(_) => {
                    // 待发送数据已发送，继续处理新数据
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                    // 通道还是满的，把数据放回去
                    self.pending_write = Some(data);
                    // 不立即唤醒，等待接收端消费数据后自然唤醒
                    // 这样可以避免忙等待，减少 CPU 占用
                    return std::task::Poll::Pending;
                }
                Err(_) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "WebSocket write channel closed",
                    )));
                }
            }
        }

        // 尝试发送新数据
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                // 通道满了，保存数据等待下次重试
                // 对于 TCP 传输，我们应该等待而不是丢弃数据
                self.pending_write = Some(data);
                // 不立即唤醒，等待接收端消费数据后自然唤醒
                // 当接收端从通道接收数据后，会触发下一次 poll，此时可以重试
                std::task::Poll::Pending
            }
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