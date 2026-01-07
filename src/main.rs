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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use anyhow::{Result, anyhow};
use tokio_rustls::{TlsAcceptor};
use bytes::Bytes;

const BUF_SIZE: usize = 32 * 1024;
const UDP_CHANNEL_BUFFER_SIZE: usize = 64;
const TCP_IDLE_TIMEOUT_SECS: u64 = 60;

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

async fn process_trojan<S: AsyncRead + AsyncWrite + Unpin + 'static>(
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
            handle_udp_associate(server, stream, request.addr, peer_addr).await
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
    let mut remote_stream = TcpStream::connect(remote_addr).await?;
    log::info!(peer = %peer_addr, remote = %remote_addr, "Connected to remote server");

    if !initial_payload.is_empty() {
        remote_stream.write_all(&initial_payload).await?;
    }

    // 双向转发
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote_stream);

    let start_time = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));

    let last_activity_clone1 = Arc::clone(&last_activity);
    let last_activity_clone2 = Arc::clone(&last_activity);
    let start_time_clone = start_time;

    let client_to_remote = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 { break; }
            last_activity_clone1.store(start_time_clone.elapsed().as_nanos() as u64, Ordering::Relaxed);
            remote_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let remote_to_client = async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = remote_read.read(&mut buf).await?;
            if n == 0 { break; }
            last_activity_clone2.store(start_time_clone.elapsed().as_nanos() as u64, Ordering::Relaxed);
            client_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let timeout_check = async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let timeout_nanos = (TCP_IDLE_TIMEOUT_SECS as u64) * 1_000_000_000;
        loop {
            interval.tick().await;
            let last_nanos = last_activity.load(Ordering::Relaxed);
            let elapsed_nanos = start_time.elapsed().as_nanos() as u64;
            if elapsed_nanos.saturating_sub(last_nanos) >= timeout_nanos {
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

async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin>(
    server: Arc<Server>,
    mut client_stream: S,
    _bind_addr: socks5::Address,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, "Starting UDP associate");
    
    let socket_key = format!("client_{}_{}", peer_addr, 
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis());
    
    let udp_association = {
        let mut associations = server.udp_associations.lock().await;
        let bind_socket_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 
            0
        );
        let socket = UdpSocket::bind(bind_socket_addr).await?;
        let association = udp::UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (udp_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Bytes)>(UDP_CHANNEL_BUFFER_SIZE);
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    
    // 简化UDP处理逻辑，直接丢弃旧数据，不使用额外的循环缓冲区
    let udp_recv_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            tokio::select! {
                _ = &mut cancel_rx => break,
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from_addr)) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            *activity_tracker.lock().await = now;
                            
                            // 使用Bytes::copy_from_slice，避免to_vec()复制
                            let data = Bytes::copy_from_slice(&buf[..len]);
                            
                            // 尝试发送，如果通道满了就丢弃（不阻塞）
                            let _ = udp_tx_clone.try_send((from_addr, data));
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let result = async {
        let mut read_buf = vec![0u8; BUF_SIZE];
        loop {
            tokio::select! {
                // 从客户端读取 UDP 数据包
                read_result = client_stream.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => break,
                        Ok(n) => {
                            match udp::UdpPacket::decode(&read_buf[..n]) {
                                Ok((udp_packet, _)) => {
                                    udp_association.update_activity().await;
                                    match udp_packet.addr.to_socket_addr().await {
                                        Ok(remote_addr) => {
                                            let _ = udp_association.socket
                                                .send_to(&udp_packet.payload, remote_addr).await;
                                        }
                                        Err(_) => {}
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Err(_) => break,
                    }
                }
                
                // 将 UDP 响应发送回客户端
                udp_msg = udp_rx.recv() => {
                    match udp_msg {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
                            };
                            
                            let udp_packet = udp::UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };
                            
                            let encoded = udp_packet.encode();
                            if client_stream.write_all(&encoded).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    let _ = cancel_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), udp_recv_handle).await;
    
    {
        let mut associations = server.udp_associations.lock().await;
        associations.remove(&socket_key);
    }

    result
}

// ============ 连接检测与分发 ============
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
            // 创建 gRPC 连接管理器，支持多路复用（兼容 v2ray）
            let grpc_conn = grpc::GrpcH2cConnection::new(stream).await?;
            // 运行连接管理器，为每个流启动独立的处理任务
            grpc_conn.run(move |transport| {
                let server = Arc::clone(&server);
                let peer_addr = peer_addr.clone();
                async move {
                    handle_connection(server, transport, peer_addr).await
                }
            }).await?;
            Ok(())
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

        // UDP 清理任务
        let server_cleanup = Arc::clone(&server);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(udp::UDP_TIMEOUT / 2));
            loop {
                interval.tick().await;
                let mut associations = server_cleanup.udp_associations.lock().await;
                let mut keys_to_remove = Vec::new();
                
                for (key, association) in associations.iter() {
                    if association.is_inactive(udp::UDP_TIMEOUT).await {
                        keys_to_remove.push(key.clone());
                    }
                }
                
                for key in keys_to_remove {
                    associations.remove(&key);
                }
            }
        });

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    log::connection(&addr.to_string(), "new");
                    let server_clone = Arc::clone(&server);
                    
                    tokio::spawn(async move {
                        let peer_addr = addr.to_string();
                        let result = async {
                            if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                match tls_acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        log::info!(peer = %peer_addr, "TLS handshake successful");
                                        accept_connection(server_clone, tls_stream, peer_addr.clone()).await
                                    }
                                    Err(e) => {
                                        log::error!(peer = %peer_addr, error = %e, "TLS handshake failed");
                                        Err(anyhow!("TLS handshake failed: {}", e))
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