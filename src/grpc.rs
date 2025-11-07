use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::{Bytes, BytesMut};
use anyhow::{Result, anyhow};

/// gRPC 传输层适配器
/// 将 gRPC 双向流转换为 AsyncRead + AsyncWrite trait
pub struct GrpcTransport {
    read_buffer: BytesMut,
    rx: mpsc::UnboundedReceiver<Bytes>,
    tx: mpsc::UnboundedSender<Bytes>,
}

impl GrpcTransport {
    pub fn new(
        rx: mpsc::UnboundedReceiver<Bytes>,
        tx: mpsc::UnboundedSender<Bytes>,
    ) -> Self {
        Self {
            read_buffer: BytesMut::with_capacity(8192),
            rx,
            tx,
        }
    }
}

impl AsyncRead for GrpcTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 如果缓冲区有数据，直接读取
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let data = self.read_buffer.split_to(to_read);
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }

        // 尝试从通道接收数据
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_read = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_read]);
                
                // 如果有剩余数据，放入缓冲区
                if to_read < data.len() {
                    self.read_buffer.extend_from_slice(&data[to_read..]);
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // 通道关闭，返回 EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.tx.send(Bytes::copy_from_slice(buf)) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "gRPC channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // gRPC 流不需要显式 flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 关闭发送通道
        Poll::Ready(Ok(()))
    }
}

// ============ gRPC 服务定义 ============

pub mod trojan_grpc {
    tonic::include_proto!("trojan");
}

use trojan_grpc::trojan_service_server::{TrojanService, TrojanServiceServer};
use trojan_grpc::{TunnelRequest, TunnelResponse};
use tonic::{Request, Response, Status, Streaming};
use std::sync::Arc;
use crate::Server;

pub struct TrojanGrpcService {
    server: Arc<Server>,
}

impl TrojanGrpcService {
    pub fn new(server: Arc<Server>) -> Self {
        Self { server }
    }
}

#[tonic::async_trait]
impl TrojanService for TrojanGrpcService {
    type TunnelStream = UnboundedReceiverStream<Result<TunnelResponse, Status>>;

    async fn tunnel(
        &self,
        request: Request<Streaming<TunnelRequest>>,
    ) -> Result<Response<Self::TunnelStream>, Status> {
        let peer_addr = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        println!("[gRPC] New tunnel connection from: {}", peer_addr);

        let mut in_stream = request.into_inner();
        let (client_tx, mut client_rx) = mpsc::unbounded_channel();
        let (server_tx, server_rx) = mpsc::unbounded_channel();

        // 创建 gRPC 传输适配器
        let grpc_transport = GrpcTransport::new(server_rx, client_tx.clone());

        // 启动接收任务：从 gRPC 流读取数据并发送到传输层
        tokio::spawn(async move {
            while let Ok(Some(request)) = in_stream.message().await {
                if server_tx.send(Bytes::from(request.data)).is_err() {
                    break;
                }
            }
        });

        // 启动 Trojan 处理任务
        let server_clone = Arc::clone(&self.server);
        let client_tx_clone = client_tx.clone();
        let peer_addr_clone = peer_addr.clone();
        
        tokio::spawn(async move {
            let result = crate::handle_connection(
                server_clone,
                grpc_transport,
                peer_addr_clone.clone(),
            ).await;

            if let Err(e) = result {
                println!("[gRPC] Connection error: {}", e);
            }
            
            // 连接结束，关闭通道
            drop(client_tx_clone);
        });

        // 创建响应流
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        
        tokio::spawn(async move {
            while let Some(data) = client_rx.recv().await {
                let response = TunnelResponse {
                    data: data.to_vec(),
                };
                
                if response_tx.send(Ok(response)).is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(UnboundedReceiverStream::new(response_rx)))
    }
}

/// 创建 gRPC 服务器
pub fn create_grpc_service(server: Arc<Server>) -> TrojanServiceServer<TrojanGrpcService> {
    let service = TrojanGrpcService::new(server);
    TrojanServiceServer::new(service)
}

/// 运行 gRPC 服务器
pub async fn run_grpc_server(
    server: Arc<Server>,
    grpc_addr: String,
) -> Result<()> {
    let addr = grpc_addr.parse()?;
    let service = create_grpc_service(server);

    println!("gRPC server listening on: {}", addr);

    tonic::transport::Server::builder()
        .add_service(service)
        .serve(addr)
        .await
        .map_err(|e| anyhow!("gRPC server error: {}", e))?;

    Ok(())
}