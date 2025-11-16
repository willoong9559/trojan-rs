mod utils;
mod udp;
mod socks5;
mod config;
mod tls;
mod ws;
mod grpc;
mod buffer_pool;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use anyhow::{Result, anyhow};
use tokio_rustls::{TlsAcceptor};

const BUF_SIZE: usize = 8192;
// UDP 通道缓冲区大小（更大，因为 UDP 用于实时应用如视频/游戏，需要更大的缓冲）
const UDP_CHANNEL_BUFFER_SIZE: usize = 128;

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
    pub payload: Vec<u8>,
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
                let domain = String::from_utf8(buf[cursor..cursor + domain_len].to_vec())?;
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

        let payload = buf[cursor..].to_vec();

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
        println!("[{}] Incorrect password from {}", 
            match server.transport_mode {
                TransportMode::Tcp => "TCP",
                TransportMode::WebSocket => "WS",
                TransportMode::Grpc => "gRPC",
            }, peer_addr);
        return Err(anyhow!("Incorrect password"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(stream, request.addr, request.payload, peer_addr).await
        }
        TrojanCmd::UdpAssociate => {
            handle_udp_associate(server, stream, request.addr, peer_addr).await
        }
    }
}

// ============ 统一的 CONNECT 处理 ============

async fn handle_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client_stream: S,
    target_addr: socks5::Address,
    initial_payload: Vec<u8>,
    peer_addr: String,
) -> Result<()> {
    println!("[CONNECT] Connecting to target: {}", target_addr.to_key());
    
    let remote_addr = target_addr.to_socket_addr().await?;
    let mut remote_stream = TcpStream::connect(remote_addr).await?;
    println!("[CONNECT] Connected to remote server: {}", remote_addr);

    // 发送初始载荷
    if !initial_payload.is_empty() {
        remote_stream.write_all(&initial_payload).await?;
    }

    // 双向转发
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote_stream);

    let client_to_remote = async {
        // 使用内存池复用缓冲区
        let pool = buffer_pool::get_global_pool();
        let mut buf = pool.acquire();
        let mut flush_counter = 0u32;
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 { break; }
            // 使用 write_all 确保数据完整写入，避免部分写入导致的数据堆积
            remote_write.write_all(&buf[..n]).await?;
            // 每 10 次写入 flush 一次，提高性能
            flush_counter += 1;
            if flush_counter >= 10 {
                remote_write.flush().await?;
                flush_counter = 0;
            }
        }
        // 最后确保所有数据都刷新
        remote_write.flush().await?;
        // 归还缓冲区到池中
        pool.release(buf);
        Ok::<(), anyhow::Error>(())
    };

    let remote_to_client = async {
        // 使用内存池复用缓冲区
        let pool = buffer_pool::get_global_pool();
        let mut buf = pool.acquire();
        let mut flush_counter = 0u32;
        loop {
            let n = remote_read.read(&mut buf).await?;
            if n == 0 { break; }
            // 使用 write_all 确保数据完整写入
            client_write.write_all(&buf[..n]).await?;
            // 每 10 次写入 flush 一次
            flush_counter += 1;
            if flush_counter >= 10 {
                client_write.flush().await?;
                flush_counter = 0;
            }
        }
        // 最后确保所有数据都刷新
        client_write.flush().await?;
        // 归还缓冲区到池中
        pool.release(buf);
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = client_to_remote => {
            if let Err(e) = result {
                println!("[CONNECT] Client to remote error: {}", e);
            }
        },
        result = remote_to_client => {
            if let Err(e) = result {
                println!("[CONNECT] Remote to client error: {}", e);
            }
        },
    }

    println!("[CONNECT] Connection closed for {}", peer_addr);
    Ok(())
}

async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin>(
    server: Arc<Server>,
    mut client_stream: S,
    _bind_addr: socks5::Address,
    peer_addr: String,
) -> Result<()> {
    println!("[UDP] Starting UDP associate for {}", peer_addr);
    
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

    let (udp_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(UDP_CHANNEL_BUFFER_SIZE);
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    
    // 使用循环缓冲区实现丢弃旧数据保留新数据的逻辑
    let udp_buffer = Arc::new(Mutex::new(VecDeque::<(SocketAddr, Vec<u8>)>::with_capacity(UDP_CHANNEL_BUFFER_SIZE)));
    let udp_buffer_clone = Arc::clone(&udp_buffer);
    
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
                            
                            let data = buf[..len].to_vec();
                            
                            // 先尝试直接发送到通道
                            match udp_tx_clone.try_send((from_addr.clone(), data.clone())) {
                                Ok(_) => {
                                    // 发送成功，清空缓冲区（如果有的话）
                                    let mut buffer = udp_buffer_clone.lock().await;
                                    buffer.clear();
                                }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // 通道满了，将数据放入循环缓冲区
                                    let mut buffer = udp_buffer_clone.lock().await;
                                    
                                    // 如果缓冲区也满了，丢弃最旧的数据（FIFO）
                                    if buffer.len() >= UDP_CHANNEL_BUFFER_SIZE {
                                        let _ = buffer.pop_front();
                                    }
                                    
                                    // 将新数据添加到缓冲区末尾
                                    buffer.push_back((from_addr, data));
                                }
                                Err(_) => {
                                    // 通道关闭，退出循环
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    
    // 启动一个任务，持续从缓冲区向通道发送数据（丢弃旧数据保留新数据）
    let udp_buffer_sender = Arc::clone(&udp_buffer);
    let udp_tx_sender = udp_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            
            let mut buffer = udp_buffer_sender.lock().await;
            // 持续尝试发送缓冲区中的数据
            while let Some((from_addr, data)) = buffer.pop_front() {
                match udp_tx_sender.try_send((from_addr, data)) {
                    Ok(_) => {
                        // 发送成功，继续处理下一个
                    }
                    Err(mpsc::error::TrySendError::Full((from_addr, data))) => {
                        // 通道还是满的，把数据放回缓冲区前面（这样下次会优先处理）
                        buffer.push_front((from_addr, data));
                        break;
                    }
                    Err(_) => {
                        // 通道关闭，清空缓冲区并退出
                        buffer.clear();
                        return;
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
        println!("Server started, listening on {}", server.listener.local_addr()?);
        println!("Mode: {} mode", {
                match server.transport_mode {
                    TransportMode::Tcp => "TCP",
                    TransportMode::WebSocket => "WebSocket",
                    TransportMode::Grpc => "gRPC",
                }
            }
        );
        
        if server.tls_acceptor.is_some() {
            println!("TLS: enabled");
        } else {
            println!("TLS: disabled (plain mode)");
        }

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
                    println!("New connection from: {}", addr);
                    let server_clone = Arc::clone(&server);
                    
                    tokio::spawn(async move {
                        let peer_addr = addr.to_string();
                        let result = async {
                            if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                match tls_acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        println!("[{}] TLS handshake successful", peer_addr);
                                        accept_connection(server_clone, tls_stream, peer_addr.clone()).await
                                    }
                                    Err(e) => {
                                        Err(anyhow!("TLS handshake failed: {}", e))
                                    }
                                }
                            } else {
                                accept_connection(server_clone, stream, peer_addr.clone()).await
                            }
                        }.await;

                        if let Err(e) = result {
                            println!("[{}] Connection error: {}", peer_addr, e);
                        } else {
                            println!("[{}] Connection closed successfully", peer_addr);
                        }
                    });
                }
                Err(e) => {
                    println!("Failed to accept connection: {}", e);
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
        udp_associations: Arc::new(Mutex::new(HashMap::new())),
        tls_acceptor,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::ServerConfig::load()?;
    let server = build_server(config).await?;
    server.run().await
}