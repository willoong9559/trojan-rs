mod utils;
mod udp;
mod socks5;
mod config;
mod tls;
mod ws;
mod grpc;
mod error;
mod logger;

use logger::log;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use anyhow::{Result, anyhow};
use tokio_rustls::{TlsAcceptor};
use bytes::Bytes;

const BUF_SIZE: usize = 4 * 1024;

const CONNECTION_TIMEOUT_SECS: u64 = 300;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Copy)]
pub enum TransportMode {
    Tcp,
    WebSocket,
    Grpc,
}

pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56],
    pub transport_mode: TransportMode,
    pub enable_udp: bool,
    pub udp_associations: Arc<Mutex<HashMap<String, udp::UdpAssociation>>>,
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
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 59 {
            return Err(anyhow!("Buffer too small"));
        }

        let mut cursor = 0;

        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after password"));
        }
        cursor += 2;

        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("Invalid command")),
        };
        cursor += 1;

        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("Buffer too small for IPv4"));
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
                    return Err(anyhow!("Buffer too small for domain length"));
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Err(anyhow!("Buffer too small for domain"));
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
                    return Err(anyhow!("Buffer too small for IPv6"));
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

        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after address"));
        }
        cursor += 2;

        let payload = Bytes::copy_from_slice(&buf[cursor..]);

        Ok((TrojanRequest {
            password,
            cmd,
            addr,
            payload,
        }, cursor))
    }
}

async fn handle_connection<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: String,
) -> Result<()>
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
    // 读取 Trojan 请求
    let mut buf = vec![0u8; BUF_SIZE];
    let n = stream.read(&mut buf).await?;
    
    if n == 0 {
        return Err(anyhow!("Connection closed before receiving request"));
    }

    let (request, _consumed) = TrojanRequest::decode(&buf[..n])?;

    // 验证密码
    if request.password != server.password {
        let transport = match server.transport_mode {
            TransportMode::Tcp => "TCP",
            TransportMode::WebSocket => "WS",
            TransportMode::Grpc => "gRPC",
        };
        log::authentication(&peer_addr, false);
        log::warn!(peer = %peer_addr, transport = transport, "Incorrect password");
        return Err(anyhow!("Incorrect password"));
    }
    
    log::authentication(&peer_addr, true);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(stream, request.addr, request.payload, peer_addr).await
        }
        TrojanCmd::UdpAssociate => {
            if !server.enable_udp {
                log::warn!(peer = %peer_addr, "UDP associate request rejected: UDP support is disabled");
                return Err(anyhow!("UDP support is disabled"));
            }
            udp::handle_udp_associate(Arc::clone(&server.udp_associations), stream, request.addr, peer_addr).await
        }
    }
}

// 统一的 CONNECT 处理

async fn handle_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client_stream: S,
    target_addr: socks5::Address,
    initial_payload: Bytes,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, target = %target_addr.to_key(), "Connecting to target");
    
    let remote_addr = target_addr.to_socket_addr().await?;
    let mut remote_stream = match tokio::time::timeout(
        tokio::time::Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::warn!(peer = %peer_addr, timeout_secs = TCP_CONNECT_TIMEOUT_SECS, "TCP connect timeout");
            return Err(anyhow!(
                "TCP connect timeout after {} seconds",
                TCP_CONNECT_TIMEOUT_SECS
            ));
        }
    };
    log::info!(peer = %peer_addr, remote = %remote_addr, "Connected to remote server");

    if !initial_payload.is_empty() {
        remote_stream.write_all(&initial_payload).await?;
    }

    // 双向转发
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote_stream);

    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let last_activity_clone1 = Arc::clone(&last_activity);
    let last_activity_clone2 = Arc::clone(&last_activity);

    if !initial_payload.is_empty() {
        *last_activity.lock().await = Instant::now();
    }

    let peer_addr_for_log1 = peer_addr.clone();
    let peer_addr_for_log2 = peer_addr.clone();
    
    let client_to_remote = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = remote_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    *last_activity_clone1.lock().await = Instant::now();
                    if let Err(e) = remote_write.write_all(&buf[..n]).await {
                        log::debug!(peer = %peer_addr_for_log1, error = %e, "Error writing to remote");
                        break;
                    }
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr_for_log1, error = %e, "Error reading from client");
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let remote_to_client = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match remote_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = client_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    *last_activity_clone2.lock().await = Instant::now();
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        log::debug!(peer = %peer_addr_for_log2, error = %e, "Error writing to client");
                        break;
                    }
                }
                Err(e) => {
                    log::debug!(peer = %peer_addr_for_log2, error = %e, "Error reading from remote");
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let timeout_check = async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        interval.tick().await;
        let timeout_duration = tokio::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS);
        loop {
            interval.tick().await;
            let last_activity_guard = last_activity.lock().await;
            let idle_time = last_activity_guard.elapsed();
            if idle_time >= timeout_duration {
                log::warn!(peer = %peer_addr, idle_secs = idle_time.as_secs(), "Connection timeout due to inactivity");
                return Ok::<(), anyhow::Error>(());
            }
        }
    };

    tokio::select! {
        _ = client_to_remote => {},
        _ = remote_to_client => {},
        _ = timeout_check => {},
    }

    Ok(())
}


// 连接检测与分发
pub async fn accept_connection<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match server.transport_mode {
        TransportMode::Grpc => {
            let peer_addr_for_log = peer_addr.clone();
            log::info!(peer = %peer_addr_for_log, "gRPC connection established, waiting for streams");
            let grpc_conn = grpc::GrpcH2cConnection::new(stream).await?;
            let result = grpc_conn.run(move |transport| {
                let server = Arc::clone(&server);
                let peer_addr = peer_addr.clone();
                async move {
                    handle_connection(server, transport, peer_addr).await
                }
            }).await;
            
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
            let ws_stream = tokio_tungstenite::accept_async(stream).await?;
            let ws_transport = ws::WebSocketTransport::new(ws_stream);
            handle_connection(server, ws_transport, peer_addr).await
        }
        TransportMode::Tcp => {
            handle_connection(server, stream, peer_addr).await
        }
    }
}

impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        let addr = server.listener.local_addr()?;
        let mode = match server.transport_mode {
            TransportMode::Tcp => "TCP",
            TransportMode::WebSocket => "WebSocket",
            TransportMode::Grpc => "gRPC",
        };
        let tls_enabled = server.tls_acceptor.is_some();
        
        log::info!(address = %addr, mode = mode, tls = tls_enabled, "Server started");

        // UDP清理任务
        udp::start_cleanup_task(Arc::clone(&server.udp_associations));

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    log::connection(&addr.to_string(), "new");
                    let server_clone = Arc::clone(&server);
                    
                    tokio::spawn(async move {
                        let peer_addr = addr.to_string();
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
    let addr: String = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(addr).await?;
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
        enable_udp: config.enable_udp,
        udp_associations: Arc::new(Mutex::new(HashMap::new())),
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