mod config;
mod error;
mod grpc;
mod logger;
mod relay;
mod socks5;
mod tls;
mod udp;
mod utils;
mod ws;

use logger::log;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const BUF_SIZE: usize = 32 * 1024;

pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

impl Listener {
    pub fn local_addr_string(&self) -> Result<String> {
        match self {
            Listener::Tcp(l) => Ok(l.local_addr()?.to_string()),
            #[cfg(unix)]
            Listener::Unix(l) => {
                let addr = l.local_addr()?;
                if let Some(path) = addr.as_pathname() {
                    Ok(path.to_string_lossy().into_owned())
                } else {
                    Ok("[unnamed unix socket]".to_string())
                }
            }
        }
    }

    pub async fn accept(&self) -> Result<(ConnectionStream, String)> {
        match self {
            Listener::Tcp(l) => {
                let (stream, addr) = l.accept().await?;
                let _ = stream.set_nodelay(true);
                Ok((ConnectionStream::Tcp { stream }, addr.to_string()))
            }
            #[cfg(unix)]
            Listener::Unix(l) => {
                let (stream, addr) = l.accept().await?;
                let peer_addr = if let Some(path) = addr.as_pathname() {
                    format!("unix:{}", path.to_string_lossy())
                } else {
                    "unix:[unnamed]".to_string()
                };
                Ok((ConnectionStream::Unix { stream }, peer_addr))
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[project = ConnectionStreamProj]
    pub enum ConnectionStream {
        Tcp { #[pin] stream: TcpStream },
        #[cfg(unix)]
        Unix { #[pin] stream: tokio::net::UnixStream },
    }
}

impl AsyncRead for ConnectionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            ConnectionStreamProj::Tcp { stream } => stream.poll_read(cx, buf),
            #[cfg(unix)]
            ConnectionStreamProj::Unix { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ConnectionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.project() {
            ConnectionStreamProj::Tcp { stream } => stream.poll_write(cx, buf),
            #[cfg(unix)]
            ConnectionStreamProj::Unix { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            ConnectionStreamProj::Tcp { stream } => stream.poll_flush(cx),
            #[cfg(unix)]
            ConnectionStreamProj::Unix { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            ConnectionStreamProj::Tcp { stream } => stream.poll_shutdown(cx),
            #[cfg(unix)]
            ConnectionStreamProj::Unix { stream } => stream.poll_shutdown(cx),
        }
    }
}

const CONNECTION_TIMEOUT_SECS: u64 = 300;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;
const HAPPY_EYEBALLS_STAGGER_MS: u64 = 250;
const REQUEST_HEADER_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    Tcp,
    WebSocket,
    Grpc,
}

pub struct Server {
    pub listener: Listener,
    pub password: [u8; 56],
    pub transport_mode: TransportMode,
    pub ws_host: Option<String>,
    pub ws_path: Option<String>,
    pub grpc_service_name: Option<String>,
    pub enable_udp: bool,
    pub tls_acceptor: Option<TlsAcceptor>,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Ok = 0,
    ErrRead = 1,
    ErrWrite = 2,
    ErrResolve = 3,
    MoreData = 4,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrojanCmd {
    Connect = 1,
    UdpAssociate = 3,
}

#[derive(Debug)]
pub struct TrojanRequest {
    pub password: [u8; 56],
    pub cmd: TrojanCmd,
    pub addr: socks5::Address,
    pub payload: Bytes,
}

impl TrojanRequest {
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        // Minimum bytes required up to ATYP field: password(56) + CRLF(2) + cmd(1) + atyp(1)
        if buf.len() < 60 {
            return Ok(None);
        }

        let mut cursor = 0;

        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        if buf.len() < cursor + 2 {
            return Ok(None);
        }
        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after password"));
        }
        cursor += 2;

        if buf.len() <= cursor {
            return Ok(None);
        }
        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("Invalid command")),
        };
        cursor += 1;

        if buf.len() <= cursor {
            return Ok(None);
        }
        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                if buf.len() < cursor + 6 {
                    return Ok(None);
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv4(ip, port)
            }
            3 => {
                if buf.len() <= cursor {
                    return Ok(None);
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Ok(None);
                }
                let domain = std::str::from_utf8(&buf[cursor..cursor + domain_len])
                    .map_err(|e| anyhow!("Invalid UTF-8 domain: {}", e))?
                    .to_string();
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::Domain(domain, port)
            }
            4 => {
                if buf.len() < cursor + 18 {
                    return Ok(None);
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("Invalid address type")),
        };

        if buf.len() < cursor + 2 {
            return Ok(None);
        }
        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after address"));
        }
        cursor += 2;

        let payload = Bytes::copy_from_slice(&buf[cursor..]);

        Ok(Some((
            TrojanRequest {
                password,
                cmd,
                addr,
                payload,
            },
            cursor,
        )))
    }
}

async fn handle_connection<S>(server: Arc<Server>, stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 只需要一套 Trojan 协议处理逻辑
    process_trojan(server, stream, peer_addr).await
}

async fn process_trojan<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    server: Arc<Server>,
    mut stream: S,
    peer_addr: String,
) -> Result<()> {
    let request = read_trojan_request(&mut stream).await?;

    // 验证密码
    if request.password != server.password {
        log_incorrect_password(server.transport_mode, &peer_addr);
        return Err(anyhow!("Incorrect password"));
    }

    log::authentication(&peer_addr, true);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(&mut stream, request.addr, request.payload, peer_addr).await
        }
        TrojanCmd::UdpAssociate => {
            if !server.enable_udp {
                log::warn!(peer = %peer_addr, "UDP associate request rejected: UDP support is disabled");
                return Err(anyhow!("UDP support is disabled"));
            }
            udp::handle_udp_associate(
                stream,
                request.addr,
                request.payload,
                peer_addr,
            )
            .await
        }
    }
}

async fn process_grpc_stream<S>(
    password: [u8; 56],
    enable_udp: bool,
    mut stream: S,
    peer_addr: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = match read_trojan_request(&mut stream).await {
        Ok(request) => request,
        Err(e) => return finish_grpc_stream(&mut stream, Err(e), &peer_addr).await,
    };

    if request.password != password {
        log_incorrect_password(TransportMode::Grpc, &peer_addr);
        return finish_grpc_stream(&mut stream, Err(anyhow!("Incorrect password")), &peer_addr)
            .await;
    }

    log::authentication(&peer_addr, true);

    match request.cmd {
        TrojanCmd::Connect => {
            let result = handle_connect(
                &mut stream,
                request.addr,
                request.payload,
                peer_addr.clone(),
            )
            .await;
            finish_grpc_stream(&mut stream, result, &peer_addr).await
        }
        TrojanCmd::UdpAssociate => {
            if !enable_udp {
                log::warn!(peer = %peer_addr, "UDP associate request rejected: UDP support is disabled");
                return finish_grpc_stream(
                    &mut stream,
                    Err(anyhow!("UDP support is disabled")),
                    &peer_addr,
                )
                .await;
            }
            udp::handle_udp_associate(
                stream,
                request.addr,
                request.payload,
                peer_addr,
            )
            .await
        }
    }
}

async fn finish_grpc_stream<S>(stream: &mut S, result: Result<()>, peer_addr: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let shutdown_result = stream.shutdown().await;
    match (result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(e),
        (Ok(()), Err(e)) => Err(e.into()),
        (Err(original), Err(shutdown_error)) => {
            log::warn!(
                peer = %peer_addr,
                error = %shutdown_error,
                "Failed to send gRPC stream trailers after handler error"
            );
            Err(original)
        }
    }
}

async fn read_trojan_request<S>(stream: &mut S) -> Result<TrojanRequest>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(
        tokio::time::Duration::from_secs(REQUEST_HEADER_TIMEOUT_SECS),
        async {
            let mut read_buf = vec![0u8; BUF_SIZE];
            let mut server_buffer = Vec::with_capacity(BUF_SIZE);

            loop {
                if server_buffer.len() >= BUF_SIZE {
                    return Err(anyhow!("Trojan request exceeds maximum buffer size"));
                }

                let remaining = BUF_SIZE - server_buffer.len();
                let read_size = remaining.min(read_buf.len());
                let n = stream.read(&mut read_buf[..read_size]).await?;

                if n == 0 {
                    if server_buffer.is_empty() {
                        return Err(anyhow!("Connection closed before receiving request"));
                    }
                    return Err(anyhow!(
                        "Connection closed before receiving complete request"
                    ));
                }

                server_buffer.extend_from_slice(&read_buf[..n]);

                if let Some((request, _consumed)) = TrojanRequest::decode(&server_buffer)? {
                    break Ok(request);
                }
            }
        },
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Timed out waiting for Trojan request header after {} seconds",
            REQUEST_HEADER_TIMEOUT_SECS
        )
    })?
}

fn log_incorrect_password(transport_mode: TransportMode, peer_addr: &str) {
    let transport = match transport_mode {
        TransportMode::Tcp => "TCP",
        TransportMode::WebSocket => "WS",
        TransportMode::Grpc => "gRPC",
    };
    log::authentication(peer_addr, false);
    log::warn!(peer = %peer_addr, transport = transport, "Incorrect password");
}

// 统一的 CONNECT 处理

async fn handle_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client_stream: &mut S,
    target_addr: socks5::Address,
    initial_payload: Bytes,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, target = %target_addr.to_key(), "Connecting to target");

    let remote_addrs = target_addr.resolve_socket_addrs().await?;
    let (mut remote_stream, remote_addr) =
        connect_first_available(&peer_addr, &remote_addrs).await?;
    log::info!(peer = %peer_addr, remote = %remote_addr, "Connected to remote server");

    if !initial_payload.is_empty() {
        remote_stream.write_all(&initial_payload).await?;
    }

    match relay::copy_bidirectional_with_idle_timeout(
        client_stream,
        remote_stream,
        CONNECTION_TIMEOUT_SECS,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            log::warn!(peer = %peer_addr, "Connection timeout due to inactivity");
        }
        Err(e) => {
            if is_benign_copy_error(&e) {
                log::info!(peer = %peer_addr, error = %e, "Connection closed by peer");
            } else {
                log::warn!(peer = %peer_addr, error = %e, "Copy bidirectional error");
            }
        }
    }

    Ok(())
}

async fn connect_first_available(
    peer_addr: &str,
    addrs: &[SocketAddr],
) -> Result<(TcpStream, SocketAddr)> {
    if addrs.is_empty() {
        return Err(anyhow!("No addresses to connect"));
    }

    let connect_timeout = Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS);
    let stagger = Duration::from_millis(HAPPY_EYEBALLS_STAGGER_MS);
    let mut attempts = tokio::task::JoinSet::new();

    for (i, &addr) in addrs.iter().enumerate() {
        let delay = stagger * i as u32;
        attempts.spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result = tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await;
            (addr, result)
        });
    }

    let mut last_error: Option<anyhow::Error> = None;
    while let Some(join_result) = attempts.join_next().await {
        match join_result {
            Ok((addr, Ok(Ok(stream)))) => {
                attempts.abort_all();
                let _ = stream.set_nodelay(true);
                return Ok((stream, addr));
            }
            Ok((addr, Ok(Err(e)))) => {
                log::debug!(
                    peer = %peer_addr,
                    remote = %addr,
                    error = %e,
                    "TCP connect failed, waiting for other addresses"
                );
                last_error = Some(e.into());
            }
            Ok((addr, Err(_))) => {
                log::debug!(
                    peer = %peer_addr,
                    remote = %addr,
                    timeout_secs = TCP_CONNECT_TIMEOUT_SECS,
                    "TCP connect timeout, waiting for other addresses"
                );
                last_error = Some(anyhow!(
                    "TCP connect timeout after {} seconds to {}",
                    TCP_CONNECT_TIMEOUT_SECS,
                    addr
                ));
            }
            Err(e) => {
                if e.is_cancelled() {
                    continue;
                }
                last_error = Some(e.into());
            }
        }
    }

    if let Some(error) = &last_error {
        log::warn!(peer = %peer_addr, error = %error, "TCP connect failed for all resolved addresses");
    }
    Err(last_error.unwrap_or_else(|| anyhow!("All connect attempts failed")))
}

fn is_benign_copy_error(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::BrokenPipe)
        && error.to_string() == "gRPC stream closed"
}

// 连接检测与分发
pub async fn accept_connection<S>(server: Arc<Server>, stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match server.transport_mode {
        TransportMode::Grpc => {
            let peer_addr_for_log = peer_addr.clone();
            log::info!(peer = %peer_addr_for_log, "gRPC connection established, waiting for streams");
            let grpc_conn = if let Some(service_name) = server.grpc_service_name.clone() {
                grpc::GrpcH2cConnection::with_service_name(stream, Some(service_name)).await?
            } else {
                grpc::GrpcH2cConnection::new(stream).await?
            };
            let result = grpc_conn
                .run(move |transport| {
                    let password = server.password;
                    let enable_udp = server.enable_udp;
                    let peer_addr = peer_addr.clone();
                    async move {
                        process_grpc_stream(
                            password,
                            enable_udp,
                            transport,
                            peer_addr,
                        )
                        .await
                    }
                })
                .await;

            match &result {
                Ok(()) => {
                    log::info!(peer = %peer_addr_for_log, "gRPC connection closed normally");
                }
                Err(e) => {
                    log::warn!(peer = %peer_addr_for_log, error = %e, "gRPC connection closed with error");
                }
            }
            result
        }
        TransportMode::WebSocket => {
            let ws_transport = ws::accept_connection(
                stream,
                peer_addr.clone(),
                server.ws_host.clone(),
                server.ws_path.clone(),
            )
            .await?;
            handle_connection(server, ws_transport, peer_addr).await
        }
        TransportMode::Tcp => handle_connection(server, stream, peer_addr).await,
    }
}

impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        let addr = server.listener.local_addr_string()?;
        let mode = match server.transport_mode {
            TransportMode::Tcp => "TCP",
            TransportMode::WebSocket => "WebSocket",
            TransportMode::Grpc => "gRPC",
        };
        let tls_enabled = server.tls_acceptor.is_some();

        log::info!(address = %addr, mode = mode, tls = tls_enabled, "Server started");

        loop {
            match server.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    log::connection(&peer_addr, "new");
                    let server_clone = Arc::clone(&server);

                    tokio::spawn(async move {
                        let result = async {
                            if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30; // TLS握手超时30秒
                                match tokio::time::timeout(
                                    tokio::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                                    tls_acceptor.accept(stream)
                                ).await {
                                    Ok(Ok(tls_stream)) => {
                                        log::info!(peer = %peer_addr, "TLS handshake successful");
                                        accept_connection(server_clone, tls_stream, peer_addr.clone()).await
                                    }
                                    Ok(Err(e)) => {
                                        log::error!(peer = %peer_addr, error = %e, "TLS handshake failed");
                                        Err(anyhow!("TLS handshake failed: {}", e))
                                    }
                                    Err(_) => {
                                        log::warn!(peer = %peer_addr, timeout_secs = TLS_HANDSHAKE_TIMEOUT_SECS, "TLS handshake timeout");
                                        Err(anyhow!("TLS handshake timeout after {} seconds", TLS_HANDSHAKE_TIMEOUT_SECS))
                                    }
                                }
                            } else {
                                accept_connection(server_clone, stream, peer_addr.clone()).await
                            }
                        }.await;

                        if let Err(e) = result {
                            log::error!(peer = %peer_addr, error = %e, "Connection error");
                        } else {
                            log::connection(&peer_addr, "closed");
                        }
                    });
                }
                Err(e) => {
                    log::error!(error = %e, "Failed to accept connection");
                    break;
                }
            }
        }

        Ok(())
    }
}

pub async fn build_server(config: config::ServerConfig) -> Result<Server> {
    let listener = if let Some(ref path) = config.unix_path {
        #[cfg(unix)]
        {
            if std::fs::metadata(path).is_ok() {
                log::info!("Removing existing Unix Domain Socket file at {}", path);
                let _ = std::fs::remove_file(path);
            }
            let unix_listener = tokio::net::UnixListener::bind(path)?;
            Listener::Unix(unix_listener)
        }
        #[cfg(not(unix))]
        {
            return Err(anyhow!("Unix Domain Sockets are not supported on this platform"));
        }
    } else {
        let addr: String = format!("{}:{}", config.host, config.port);
        let tcp_listener = TcpListener::bind(addr).await?;
        Listener::Tcp(tcp_listener)
    };

    let password = utils::password_to_hex(&config.password);
    let enable_ws = config.enable_ws;
    let enable_grpc = config.enable_grpc;
    let transport_mode = if enable_grpc {
        TransportMode::Grpc
    } else if enable_ws {
        TransportMode::WebSocket
    } else {
        TransportMode::Tcp
    };

    let tls_acceptor = tls::get_tls_acceptor(config.cert, config.key, transport_mode);

    Ok(Server {
        listener,
        password,
        transport_mode,
        ws_host: config.ws_host,
        ws_path: config.ws_path,
        grpc_service_name: config.grpc_service_name,
        enable_udp: config.enable_udp,
        tls_acceptor,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_level = logger::get_log_level_from_args();
    logger::init_logger(log_level);

    let config = config::ServerConfig::load()?;

    let server = build_server(config).await?;
    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use h2::client;
    use http::Request;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn grpc_password_failure_sends_ok_trailers() {
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let password = [0x11; 56];

        let server_task = tokio::spawn({
            async move {
                let conn = grpc::GrpcH2cConnection::new(server_io)
                    .await
                    .expect("server handshake should succeed");
                conn.run(move |transport| {
                    async move {
                        process_grpc_stream(
                            password,
                            false,
                            transport,
                            "127.0.0.1:12345".to_string(),
                        )
                        .await
                    }
                })
                .await
            }
        });

        let (mut send_request, client_conn) = client::Builder::new()
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake should succeed");
        let client_conn_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        let request = Request::builder()
            .method("POST")
            .uri("/Tun")
            .body(())
            .expect("request should be valid");
        let (response_future, mut request_stream) = send_request
            .send_request(request, false)
            .expect("request send should succeed");

        request_stream
            .send_data(
                encode_test_grpc_message(&wrong_password_connect_request()),
                true,
            )
            .expect("request body should send");

        let response = timeout(Duration::from_secs(3), response_future)
            .await
            .expect("response headers timeout")
            .expect("response future failed");
        let mut body = response.into_body();
        let trailers = timeout(Duration::from_secs(3), body.trailers())
            .await
            .expect("trailers timeout")
            .expect("trailers future failed")
            .expect("expected grpc trailers");

        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        drop(send_request);
        server_task.abort();
        client_conn_task.abort();
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_unix_domain_socket_bind_and_connect() {
        let unix_path = format!("/tmp/test_trojan_rs_uds_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&unix_path);

        let config = config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: "35537".to_string(),
            password: "test_password".to_string(),
            enable_ws: false,
            enable_grpc: false,
            ws_host: None,
            ws_path: None,
            grpc_service_name: None,
            enable_udp: false,
            cert: None,
            key: None,
            config_file: None,
            generate_config: None,
            log_level: None,
            unix_path: Some(unix_path.clone()),
        };

        let server = build_server(config).await.expect("failed to build server");
        let server_run_task = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give the server a small moment to bind/start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_stream_res: std::io::Result<tokio::net::UnixStream> = tokio::net::UnixStream::connect(&unix_path).await;
        assert!(client_stream_res.is_ok(), "Failed to connect to Unix Domain Socket: {:?}", client_stream_res.err());
        let mut client_stream = client_stream_res.unwrap();

        // Write an invalid request (to trigger a response or end of connection)
        let mut invalid_req = Vec::new();
        invalid_req.extend_from_slice(&[0x11; 56]);
        invalid_req.extend_from_slice(b"\r\n");
        invalid_req.push(TrojanCmd::Connect as u8);
        invalid_req.push(1);
        invalid_req.extend_from_slice(&[127, 0, 0, 1]);
        invalid_req.extend_from_slice(&80u16.to_be_bytes());
        invalid_req.extend_from_slice(b"\r\n");

        let write_res: std::io::Result<()> = client_stream.write_all(&invalid_req).await;
        assert!(write_res.is_ok());

        // Wait a bit, clean up task
        tokio::time::sleep(Duration::from_millis(100)).await;
        server_run_task.abort();
        let _ = std::fs::remove_file(&unix_path);
    }

    fn wrong_password_connect_request() -> Vec<u8> {
        let mut request = Vec::new();
        request.extend_from_slice(&[0x22; 56]);
        request.extend_from_slice(b"\r\n");
        request.push(TrojanCmd::Connect as u8);
        request.push(1);
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&80u16.to_be_bytes());
        request.extend_from_slice(b"\r\n");
        request
    }

    fn encode_test_grpc_message(payload: &[u8]) -> Bytes {
        let mut proto_header = BytesMut::with_capacity(10);
        proto_header.put_u8(0x0A);
        encode_test_varint(payload.len() as u64, &mut proto_header);

        let grpc_payload_len = (proto_header.len() + payload.len()) as u32;
        let mut frame = BytesMut::with_capacity(5 + proto_header.len() + payload.len());
        frame.put_u8(0x00);
        frame.put_u32(grpc_payload_len);
        frame.extend_from_slice(&proto_header);
        frame.extend_from_slice(payload);
        frame.freeze()
    }

    fn encode_test_varint(mut value: u64, buf: &mut BytesMut) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.put_u8(byte);
            if value == 0 {
                break;
            }
        }
    }
}
