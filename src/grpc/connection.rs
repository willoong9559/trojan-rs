use tokio::io::{AsyncRead, AsyncWrite};
use bytes::Bytes;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use h2::{server, Reason};
use http::{HeaderMap, Response, StatusCode};
use anyhow::Result;
use tracing::{debug, warn};
use tokio::sync::Notify;

use crate::relay::{
    NetworkBufferedIo, WriteBufferWatermark, NETWORK_BUFFER_HIGH_WATERMARK,
    NETWORK_BUFFER_LOW_WATERMARK,
};

use super::transport::GrpcH2cTransport;
use super::{
    MAX_CONCURRENT_STREAMS, MAX_HEADER_FIELD_SIZE, MAX_HEADER_LIST_SIZE,
    MAX_HEADERS_COUNT,
    INITIAL_WINDOW_SIZE, INITIAL_CONNECTION_WINDOW_SIZE, STREAM_BUFFER_HIGH_WATERMARK,
};

const HEADER_LIST_ENTRY_OVERHEAD: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestHeadersValidationError {
    TooManyHeaders { count: usize },
    HeaderFieldTooLarge { size: usize },
    HeaderListTooLarge { size: usize },
}

fn envoy_header_list_size(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| {
            name.as_str().len() + value.as_bytes().len() + HEADER_LIST_ENTRY_OVERHEAD
        })
        .sum()
}

fn validate_envoy_request_headers(
    headers: &HeaderMap,
) -> Result<(), RequestHeadersValidationError> {
    let header_count = headers.len();
    if header_count > MAX_HEADERS_COUNT {
        return Err(RequestHeadersValidationError::TooManyHeaders {
            count: header_count,
        });
    }

    for (name, value) in headers.iter() {
        let field_size = name.as_str().len().max(value.as_bytes().len());
        if field_size > MAX_HEADER_FIELD_SIZE {
            return Err(RequestHeadersValidationError::HeaderFieldTooLarge {
                size: field_size,
            });
        }
    }

    let header_list_size = envoy_header_list_size(headers);
    if header_list_size > MAX_HEADER_LIST_SIZE as usize {
        return Err(RequestHeadersValidationError::HeaderListTooLarge {
            size: header_list_size,
        });
    }

    Ok(())
}

/// gRPC HTTP/2 连接管理器
/// 
/// 管理整个 HTTP/2 连接，接受多个流，每个流对应一个独立的 Trojan 隧道
pub struct GrpcH2cConnection<S> {
    h2_conn: server::Connection<NetworkBufferedIo<S>, Bytes>,
    active_count: Arc<AtomicUsize>,
    connection_send_watermark: Arc<WriteBufferWatermark>,
}

impl<S> GrpcH2cConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn new(stream: S) -> io::Result<Self> {
        let connection_send_watermark = Arc::new(WriteBufferWatermark::new(
            NETWORK_BUFFER_HIGH_WATERMARK,
            NETWORK_BUFFER_LOW_WATERMARK,
        ));
        let stream = NetworkBufferedIo::with_write_buffer_watermark(
            stream,
            Arc::clone(&connection_send_watermark),
        );
        let h2_conn = server::Builder::new()
            .max_header_list_size(MAX_HEADER_LIST_SIZE)
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS as u32)
            .max_send_buffer_size(STREAM_BUFFER_HIGH_WATERMARK)
            .handshake(stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;
        
        Ok(Self { 
            h2_conn,
            active_count: Arc::new(AtomicUsize::new(0)),
            connection_send_watermark,
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
        let connection_send_watermark = self.connection_send_watermark;
        let all_streams_done = Arc::new(Notify::new());

        loop {
            match h2_conn.accept().await {
                Some(Ok((request, mut respond))) => {
                    match validate_envoy_request_headers(request.headers()) {
                        Ok(()) => {}
                        Err(RequestHeadersValidationError::TooManyHeaders { count }) => {
                            warn!(
                                count,
                                limit = MAX_HEADERS_COUNT,
                                "Rejecting gRPC request: too many request headers",
                            );
                            respond.send_reset(Reason::PROTOCOL_ERROR);
                            continue;
                        }
                        Err(RequestHeadersValidationError::HeaderFieldTooLarge { size }) => {
                            warn!(
                                size,
                                limit = MAX_HEADER_FIELD_SIZE,
                                "Rejecting gRPC request: request header field too large",
                            );
                            respond.send_reset(Reason::PROTOCOL_ERROR);
                            continue;
                        }
                        Err(RequestHeadersValidationError::HeaderListTooLarge { size }) => {
                            warn!(
                                size,
                                limit = MAX_HEADER_LIST_SIZE,
                                "Rejecting gRPC request: request header list too large",
                            );
                            let response = Response::builder()
                                .status(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                                .body(())
                                .unwrap();
                            let _ = respond.send_response(response, true);
                            continue;
                        }
                    }

                    if request.method() != http::Method::POST {
                        let response = Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(response, true);
                        continue;
                    }

                    let path = request.uri().path().to_owned();
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

                    let transport = GrpcH2cTransport::new(
                        request.into_body(),
                        send_stream,
                        Arc::clone(&connection_send_watermark),
                    );

                    let handler_clone = Arc::clone(&handler);
                    let active_count_clone = Arc::clone(&active_count);
                    let all_streams_done_clone = Arc::clone(&all_streams_done);
                    let active_streams = active_count_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    debug!(active_streams, path, "Accepted gRPC stream");
                    tokio::spawn(async move {
                        let result = handler_clone(transport).await;
                        let remaining_streams =
                            active_count_clone.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);

                        match result {
                            Ok(()) => {
                                debug!(active_streams = remaining_streams, "gRPC stream handler finished");
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    active_streams = remaining_streams,
                                    "gRPC stream handler failed",
                                );
                            }
                        }

                        if remaining_streams == 0 {
                            all_streams_done_clone.notify_waiters();
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
    fn validate_request_headers_accepts_envoy_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert("te", "trailers".parse().unwrap());
        headers.insert("content-type", "application/grpc".parse().unwrap());
        assert_eq!(validate_envoy_request_headers(&headers), Ok(()));
    }

    #[test]
    fn validate_request_headers_rejects_too_many_headers() {
        let mut headers = HeaderMap::new();
        for i in 0..(MAX_HEADERS_COUNT + 1) {
            let name = format!("x-test-{i}");
            headers.insert(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "1".parse().unwrap(),
            );
        }
        assert_eq!(
            validate_envoy_request_headers(&headers),
            Err(RequestHeadersValidationError::TooManyHeaders {
                count: MAX_HEADERS_COUNT + 1,
            })
        );
    }

    #[test]
    fn validate_request_headers_rejects_oversized_header_list() {
        let mut headers = HeaderMap::new();
        let oversized_value_len =
            (MAX_HEADER_LIST_SIZE as usize).saturating_sub(HEADER_LIST_ENTRY_OVERHEAD) + 1;
        headers.insert(
            "x-test",
            http::HeaderValue::from_bytes(&vec![b'a'; oversized_value_len]).unwrap(),
        );
        assert_eq!(
            validate_envoy_request_headers(&headers),
            Err(RequestHeadersValidationError::HeaderListTooLarge {
                size: envoy_header_list_size(&headers),
            })
        );
    }

    #[tokio::test]
    async fn stream_failure_does_not_fail_connection() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let stream_count = Arc::new(AtomicUsize::new(0));

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            conn
                .run({
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
    async fn too_many_headers_resets_stream_without_failing_connection() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let stream_count = Arc::new(AtomicUsize::new(0));
        let stream_count_for_server = Arc::clone(&stream_count);

        let server_task = tokio::spawn(async move {
            let conn = GrpcH2cConnection::new(server_io)
                .await
                .expect("server handshake should succeed");
            conn
                .run({
                    let stream_count = Arc::clone(&stream_count_for_server);
                    move |mut transport| {
                        let stream_count = Arc::clone(&stream_count);
                        async move {
                            stream_count.fetch_add(1, Ordering::Relaxed);
                            transport.shutdown().await?;
                            Ok(())
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

        let oversized_request = {
            let mut builder = Request::builder().method("POST").uri("/Tun");
            for i in 0..(MAX_HEADERS_COUNT + 1) {
                let name = format!("x-test-{i}");
                builder = builder.header(name, "1");
            }
            builder.body(()).expect("request should be valid")
        };
        let (oversized_response, _) = send_request
            .send_request(oversized_request, true)
            .expect("oversized request send should succeed");
        let oversized_error = timeout(Duration::from_secs(3), oversized_response)
            .await
            .expect("oversized response timeout")
            .expect_err("oversized request should be reset");
        assert!(oversized_error.to_string().contains("stream"));

        let valid_request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .header("te", "trailers")
            .header("content-type", "application/grpc")
            .body(())
            .expect("request should be valid");
        let (valid_response, _) = send_request
            .send_request(valid_request, true)
            .expect("valid request send should succeed");
        let valid_response = timeout(Duration::from_secs(3), valid_response)
            .await
            .expect("valid response timeout")
            .expect("valid response future failed");
        let mut valid_body = valid_response.into_body();
        let trailers = timeout(Duration::from_secs(3), valid_body.trailers())
            .await
            .expect("trailers timeout")
            .expect("trailers future failed")
            .expect("expected grpc trailers");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        assert_eq!(stream_count.load(Ordering::Relaxed), 1);

        drop(send_request);
        server_task.abort();
        client_conn_task.abort();
    }
}
