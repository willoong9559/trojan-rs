use anyhow::Result;
use bytes::Bytes;
use futures_util::FutureExt;
use h2::server;
use http::{Response, StatusCode};
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tokio::time::Duration;
use tracing::{debug, info, warn};

use super::transport::GrpcH2cTransport;
use super::{MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE, MAX_SEND_QUEUE_BYTES};

const GRPC_CONNECTION_IDLE_TIMEOUT_SECS: u64 = 600;

struct ActiveStreamGuard {
    active_count: Option<Arc<AtomicUsize>>,
    all_streams_done: Arc<Notify>,
}

impl ActiveStreamGuard {
    fn new(active_count: Arc<AtomicUsize>, all_streams_done: Arc<Notify>) -> Self {
        Self {
            active_count: Some(active_count),
            all_streams_done,
        }
    }

    fn finish(mut self) -> usize {
        self.decrement().unwrap_or(0)
    }

    fn decrement(&mut self) -> Option<usize> {
        let active_count = self.active_count.take()?;
        let remaining_streams = active_count
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);

        if remaining_streams == 0 {
            self.all_streams_done.notify_one();
        }

        Some(remaining_streams)
    }
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        let _ = self.decrement();
    }
}

/// gRPC HTTP/2 连接管理器
///
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<S, Bytes>,
    active_count: Arc<AtomicUsize>,
    expected_service_name: Option<String>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
        Self::with_service_name(stream, None).await
    }

    pub async fn with_service_name(
        stream: S,
        expected_service_name: Option<String>,
    ) -> io::Result<Self> {
        let h2_conn = server::Builder::new()
            .max_frame_size(MAX_FRAME_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS as u32)
            .max_send_buffer_size(MAX_SEND_QUEUE_BYTES)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;

        Ok(Self {
            h2_conn,
            active_count: Arc::new(AtomicUsize::new(0)),
            expected_service_name,
        })
    }

    pub async fn run<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        self.run_with_idle_timeout(
            handler,
            Duration::from_secs(GRPC_CONNECTION_IDLE_TIMEOUT_SECS),
        )
        .await
    }

    async fn run_with_idle_timeout<F, Fut>(self, handler: F, idle_timeout: Duration) -> Result<()>
    where
        F: Fn(GrpcH2cTransport) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let mut h2_conn = self.h2_conn;
        let active_count = self.active_count;
        let expected_service_name = self.expected_service_name;
        let all_streams_done = Arc::new(Notify::new());

        loop {
            let accepted = if active_count.load(Ordering::Relaxed) == 0 {
                tokio::select! {
                    accepted = h2_conn.accept() => accepted,
                    _ = tokio::time::sleep(idle_timeout) => {
                        info!(
                            idle_timeout_secs = idle_timeout.as_secs(),
                            "Closing idle gRPC connection"
                        );
                        break;
                    }
                }
            } else {
                tokio::select! {
                    accepted = h2_conn.accept() => accepted,
                    _ = all_streams_done.notified() => continue,
                }
            };

            match accepted {
                Some(Ok((request, mut respond))) => {
                    if request.method() != http::Method::POST {
                        let response = Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    let path = request.uri().path().to_owned();
                    if !grpc_path_matches(&path, expected_service_name.as_deref()) {
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
                        .header("grpc-accept-encoding", "identity,deflate,gzip")
                        .body(())
                        .unwrap();

                    let send_stream = match respond.send_response(response, false) {
                        Ok(stream) => stream,
                        Err(e) => {
                            warn!(error = %e, "Failed to send gRPC response");
                            continue;
                        }
                    };

                    let transport = GrpcH2cTransport::new(request.into_body(), send_stream);

                    let handler_clone = Arc::clone(&handler);
                    let active_count_clone = Arc::clone(&active_count);
                    let all_streams_done_clone = Arc::clone(&all_streams_done);
                    let active_streams = active_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    debug!(active_streams, path, "Accepted gRPC stream");
                    tokio::spawn(async move {
                        let active_stream =
                            ActiveStreamGuard::new(active_count_clone, all_streams_done_clone);
                        let result = AssertUnwindSafe(handler_clone(transport))
                            .catch_unwind()
                            .await;
                        let remaining_streams = active_stream.finish();

                        match result {
                            Ok(Ok(())) => {
                                debug!(
                                    active_streams = remaining_streams,
                                    "gRPC stream handler finished"
                                );
                            }
                            Ok(Err(e)) => {
                                warn!(
                                    error = %e,
                                    active_streams = remaining_streams,
                                    "gRPC stream handler failed",
                                );
                            }
                            Err(_) => {
                                warn!(
                                    active_streams = remaining_streams,
                                    "gRPC stream handler panicked",
                                );
                            }
                        }
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

        while active_count.load(Ordering::Relaxed) > 0 {
            all_streams_done.notified().await;
        }

        Ok(())
    }
}

fn grpc_path_matches(path: &str, expected_service_name: Option<&str>) -> bool {
    match expected_service_name {
        Some(expected_service_name) => {
            grpc_service_name_from_path(path) == Some(expected_service_name)
        }
        None => path.ends_with("/Tun"),
    }
}

fn grpc_service_name_from_path(path: &str) -> Option<&str> {
    let mut segments = path.trim_start_matches('/').split('/');
    let service_name = segments.next()?;
    let method_name = segments.next()?;

    if service_name.is_empty() || method_name != "Tun" || segments.next().is_some() {
        return None;
    }

    Some(service_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use h2::client;
    use http::Request;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

    #[test]
    fn grpc_path_parser_extracts_service_name() {
        assert_eq!(
            grpc_service_name_from_path("/GunService/Tun"),
            Some("GunService")
        );
        assert_eq!(grpc_service_name_from_path("/GunService/Other"), None);
        assert_eq!(grpc_service_name_from_path("/nested/GunService/Tun"), None);
    }

    #[test]
    fn grpc_path_match_keeps_legacy_tun_compatibility_without_service_name() {
        assert!(grpc_path_matches("/Tun", None));
        assert!(grpc_path_matches("/GunService/Tun", None));
        assert!(!grpc_path_matches("/GunService/Other", None));
    }

    #[tokio::test]
    async fn stream_failure_does_not_fail_connection() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let stream_count = Arc::new(AtomicUsize::new(0));

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            conn.run({
                let stream_count = Arc::clone(&stream_count);
                move |mut transport| {
                    let stream_count = Arc::clone(&stream_count);
                    async move {
                        match stream_count.fetch_add(1, Ordering::Relaxed) {
                            0 => Err(anyhow::anyhow!("intentional stream failure")),
                            _ => {
                                transport.shutdown().await?;
                                Ok(())
                            }
                        }
                    }
                }
            })
            .await
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = || {
            Request::builder()
                .method("POST")
                .uri("/Tun")
                .body(())
                .expect("request should be valid")
        };

        let (failed_response, _) = send_request
            .send_request(request(), true)
            .expect("first request send should succeed");
        let failed_response = timeout(Duration::from_secs(3), failed_response)
            .await
            .expect("first response headers timeout")
            .expect("first response future failed");
        drop(failed_response);

        let (ok_response, _) = send_request
            .send_request(request(), true)
            .expect("second request send should succeed");
        let ok_response = timeout(Duration::from_secs(3), ok_response)
            .await
            .expect("second response headers timeout")
            .expect("second response future failed");
        let mut ok_body = ok_response.into_body();
        let trailers = timeout(Duration::from_secs(3), ok_body.trailers())
            .await
            .expect("trailers timeout")
            .expect("trailers future failed")
            .expect("expected grpc trailers");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        drop(ok_body);
        drop(send_request);
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn handler_panic_releases_active_stream() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            conn.run_with_idle_timeout(
                |_| async {
                    panic!("intentional handler panic");
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                },
                Duration::from_millis(50),
            )
            .await
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let (response, _) = send_request
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("/Tun")
                    .body(())
                    .expect("request should be valid"),
                true,
            )
            .expect("request send should succeed");

        let response = timeout(Duration::from_secs(3), response)
            .await
            .expect("response headers timeout")
            .expect("response future failed");
        drop(response);
        drop(send_request);

        timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server should not wait forever after handler panic")
            .expect("server task should not panic")
            .expect("server run should succeed");

        client_conn_task.abort();
    }

    #[tokio::test]
    async fn rejects_unexpected_grpc_service_name() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);

        let server_task = tokio::spawn(async move {
            let conn =
                GrpcH2cConnection::with_service_name(server_io, Some("GunService".to_string()))
                    .await
                    .expect("server handshake should succeed");
            conn.run(|mut transport| async move {
                transport.shutdown().await?;
                Ok(())
            })
            .await
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let (response, _) = send_request
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("/OtherService/Tun")
                    .body(())
                    .expect("request should be valid"),
                true,
            )
            .expect("request send should succeed");

        let response = timeout(Duration::from_secs(3), response)
            .await
            .expect("response headers timeout")
            .expect("response future failed");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        drop(send_request);
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    async fn closes_idle_connection_without_active_streams() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            conn.run_with_idle_timeout(|_| async { Ok(()) }, Duration::from_millis(50))
                .await
        });

        let (_send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server idle timeout should complete")
            .expect("server task should not panic")
            .expect("server run should succeed");

        client_conn_task.abort();
    }
}
