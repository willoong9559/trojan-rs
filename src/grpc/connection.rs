use tokio::io::{AsyncRead, AsyncWrite};
use bytes::Bytes;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use h2::server;
use http::{Response, StatusCode};
use anyhow::Result;
use tracing::{warn, debug};

use super::heartbeat::H2Heartbeat;
use super::transport::GrpcH2cTransport;
use super::{
    MAX_CONCURRENT_STREAMS, MAX_HEADER_LIST_SIZE,
    INITIAL_WINDOW_SIZE, INITIAL_CONNECTION_WINDOW_SIZE,
    MAX_FRAME_SIZE,
};

/// gRPC HTTP/2 连接管理器
/// 
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    active_count: Arc<AtomicUsize>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS as u32)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;
        
        Ok(Self {
            h2_conn,
            active_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let active_count = self.active_count;
        
        let mut heartbeat = H2Heartbeat::new(h2_conn.ping_pong());
        
        loop {
            tokio::select! {
                result = h2_conn.accept() => {
                    match result {
                        Some(Ok((request, mut respond))) => {
                            heartbeat.on_activity();
                            
                            if request.method() != http::Method::POST {
                                let response = Response::builder()
                                    .status(StatusCode::METHOD_NOT_ALLOWED)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            let path = request.uri().path();
                            if !path.ends_with("/Tun") {
                                let response = Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(())
                                    .unwrap();
                                let _ = respond.send_response(response, true);
                                continue;
                            }

                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/grpc")
                                .header("te", "trailers")
                                .header("grpc-accept-encoding", "identity")
                                .body(())
                                .unwrap();

                            let send_stream = match respond.send_response(response, false) {
                                Ok(stream) => stream,
                                Err(e) => {
                                    warn!(error = %e, "Failed to send gRPC response");
                                    continue;
                                }
                            };

                            let transport = GrpcH2cTransport::new(
                                request.into_body(),
                                send_stream,
                            );

                            let handler_clone = Arc::clone(&handler);
                            let active_count_clone = Arc::clone(&active_count);
                            active_count_clone.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _ = handler_clone(transport).await;
                                active_count_clone.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "gRPC connection error");
                            return Err(anyhow::anyhow!("gRPC connection error: {}", e));
                        }
                        None => {
                            debug!("gRPC connection closed normally");
                            break;
                        }
                    }
                }
                
                result = heartbeat.poll() => {
                    if let Err(e) = result {
                        return Err(anyhow::anyhow!("gRPC {}", e));
                    }
                }
            }
        }
        Ok(())
    }
}

