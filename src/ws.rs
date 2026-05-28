use crate::logger::log;
use anyhow::Result;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::{header::HOST, uri::Authority, StatusCode};
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{
            ErrorResponse as WebSocketErrorResponse, Request as WebSocketRequest,
            Response as WebSocketResponse,
        },
        Message,
    },
    WebSocketStream as TungsteniteStream,
};

pub async fn accept_connection<S>(
    stream: S,
    peer_addr: String,
    expected_host: Option<String>,
    expected_path: Option<String>,
) -> Result<WebSocketTransport<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_stream = accept_hdr_async(
        stream,
        move |request: &WebSocketRequest, response: WebSocketResponse| {
            validate_websocket_request(
                request,
                response,
                &peer_addr,
                expected_host.as_deref(),
                expected_path.as_deref(),
            )
        },
    )
    .await?;

    Ok(WebSocketTransport::new(ws_stream))
}

pub struct WebSocketTransport<S> {
    ws_stream: Pin<Box<TungsteniteStream<S>>>,
    read_buffer: Bytes,
    read_pos: usize,
    write_buffer: Vec<u8>, // 保持 Vec<u8>， WebSocket 库需要
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

fn validate_websocket_request(
    request: &WebSocketRequest,
    response: WebSocketResponse,
    peer_addr: &str,
    expected_host: Option<&str>,
    expected_path: Option<&str>,
) -> std::result::Result<WebSocketResponse, WebSocketErrorResponse> {
    if let Some(expected_path) = expected_path {
        let actual_path = request.uri().path();
        if actual_path != expected_path {
            log::warn!(
                peer = %peer_addr,
                expected_path = expected_path,
                actual_path = actual_path,
                "Rejected WebSocket handshake due to path mismatch"
            );
            return Err(websocket_error_response(
                StatusCode::NOT_FOUND,
                "Invalid WebSocket path",
            ));
        }
    }

    if let Some(expected_host) = expected_host {
        let actual_host = match request
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
        {
            Some(host) => host,
            None => {
                log::warn!(peer = %peer_addr, "Rejected WebSocket handshake due to missing Host header");
                return Err(websocket_error_response(
                    StatusCode::BAD_REQUEST,
                    "Missing WebSocket Host header",
                ));
            }
        };

        if !websocket_host_matches(expected_host, actual_host) {
            log::warn!(
                peer = %peer_addr,
                expected_host = expected_host,
                actual_host = actual_host,
                "Rejected WebSocket handshake due to Host mismatch"
            );
            return Err(websocket_error_response(
                StatusCode::FORBIDDEN,
                "Invalid WebSocket Host header",
            ));
        }
    }

    Ok(response)
}

fn websocket_error_response(status: StatusCode, message: &str) -> WebSocketErrorResponse {
    http::Response::builder()
        .status(status)
        .body(Some(message.to_string()))
        .expect("websocket rejection response should be valid")
}

fn websocket_host_matches(expected_host: &str, actual_host: &str) -> bool {
    let Some(expected) = parse_authority(expected_host) else {
        return false;
    };
    let Some(actual) = parse_authority(actual_host) else {
        return false;
    };

    expected.host == actual.host
        && expected
            .port
            .map_or(true, |expected_port| actual.port == Some(expected_port))
}

fn parse_authority(value: &str) -> Option<ParsedAuthority> {
    let authority = Authority::from_str(value.trim()).ok()?;
    Some(ParsedAuthority {
        host: authority.host().to_ascii_lowercase(),
        port: authority.port_u16(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthority {
    host: String,
    port: Option<u16>,
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
                    match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data.into())) {
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
                match Sink::start_send(self.ws_stream.as_mut(), Message::Binary(data.into())) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("WebSocket send error: {}", e),
                    ))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("WebSocket error: {}", e),
            ))),
            Poll::Pending => {
                self.write_pending = true;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 确保所有待发送的数据都已发送
        if self.write_pending {
            match Sink::poll_ready(self.ws_stream.as_mut(), cx) {
                Poll::Ready(Ok(())) => {
                    if !self.write_buffer.is_empty() {
                        let data = std::mem::take(&mut self.write_buffer);
                        match Sink::start_send(
                            self.ws_stream.as_mut(),
                            Message::Binary(data.into()),
                        ) {
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

        Sink::poll_flush(self.ws_stream.as_mut(), cx).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("WebSocket flush error: {}", e),
            )
        })
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        // 刷新所有待发送的数据
        // WebSocket 连接的关闭由底层流处理，这里只需要确保数据已刷新
        self.as_mut().poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_websocket_request, websocket_host_matches};
    use http::{Request, Response, StatusCode};

    #[test]
    fn websocket_host_match_allows_missing_expected_port() {
        assert!(websocket_host_matches(
            "cdn.example.com",
            "cdn.example.com:443"
        ));
    }

    #[test]
    fn websocket_host_match_requires_matching_explicit_port() {
        assert!(!websocket_host_matches(
            "cdn.example.com:8443",
            "cdn.example.com:443"
        ));
    }

    #[test]
    fn websocket_validation_rejects_wrong_path() {
        let request = Request::builder()
            .uri("/grpc")
            .header("host", "cdn.example.com")
            .body(())
            .unwrap();
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(())
            .unwrap();

        let error = validate_websocket_request(
            &request,
            response,
            "127.0.0.1:1000",
            Some("cdn.example.com"),
            Some("/ws"),
        )
        .unwrap_err();

        assert_eq!(error.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn websocket_validation_rejects_wrong_host() {
        let request = Request::builder()
            .uri("/ws")
            .header("host", "other.example.com")
            .body(())
            .unwrap();
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .body(())
            .unwrap();

        let error = validate_websocket_request(
            &request,
            response,
            "127.0.0.1:1000",
            Some("cdn.example.com"),
            Some("/ws"),
        )
        .unwrap_err();

        assert_eq!(error.status(), StatusCode::FORBIDDEN);
    }
}
