mod utils;
mod udp;
mod socks5;
mod config;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{StreamExt, stream::{SplitSink, SplitStream}};
use anyhow::{Result, anyhow};

// TLS support
use tokio_rustls::{TlsAcceptor};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;

const BUF_SIZE: usize = 8192;

pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56],
    pub enable_ws: bool,
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

// ============ TCP 模式处理函数 ============

async fn handle_tcp_connect<S: AsyncRead + AsyncWrite + Unpin>(
    client_stream: S,
    target_addr: socks5::Address,
    initial_payload: Vec<u8>,
    peer_addr: String,
) -> Result<()> {
    println!("[TCP] Connecting to target: {}", target_addr.to_key());
    
    let remote_addr = target_addr.to_socket_addr().await?;
    let mut remote_stream = TcpStream::connect(remote_addr).await?;
    println!("[TCP] Connected to remote server: {}", remote_addr);

    // 发送初始载荷
    if !initial_payload.is_empty() {
        remote_stream.write_all(&initial_payload).await?;
        println!("[TCP] Wrote initial payload of {} bytes", initial_payload.len());
    }

    // 双向转发
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote_stream);

    let client_to_remote = async {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            remote_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let remote_to_client = async {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = remote_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = client_to_remote => {
            if let Err(e) = result {
                println!("[TCP] Client to remote error: {}", e);
            }
        },
        result = remote_to_client => {
            if let Err(e) = result {
                println!("[TCP] Remote to client error: {}", e);
            }
        },
    }

    println!("[TCP] Connection closed for {}", peer_addr);
    Ok(())
}

async fn handle_tcp_udp_associate<S: AsyncRead + AsyncWrite + Unpin>(
    server: Arc<Server>,
    mut client_stream: S,
    _bind_addr: socks5::Address,
    peer_addr: String,
) -> Result<()> {
    println!("[TCP-UDP] Starting UDP associate for {}", peer_addr);
    
    let socket_key = format!("tcp_client_{}_{}", peer_addr, 
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
        println!("[TCP-UDP] Created UDP socket bound to: {}", socket.local_addr()?);
        
        let association = udp::UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    
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
                            
                            if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                                break;
                            }
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
                        Ok(0) => {
                            println!("[TCP-UDP] Client closed connection");
                            break;
                        }
                        Ok(n) => {
                            match udp::UdpPacket::decode(&read_buf[..n]) {
                                Ok((udp_packet, _)) => {
                                    udp_association.update_activity().await;
                                    
                                    match udp_packet.addr.to_socket_addr().await {
                                        Ok(remote_addr) => {
                                            if let Err(e) = udp_association.socket.send_to(&udp_packet.payload, remote_addr).await {
                                                println!("[TCP-UDP] Failed to send UDP: {}", e);
                                            }
                                        }
                                        Err(e) => {
                                            println!("[TCP-UDP] Failed to resolve: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("[TCP-UDP] Failed to decode packet: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("[TCP-UDP] Read error: {}", e);
                            break;
                        }
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
                            if let Err(e) = client_stream.write_all(&encoded).await {
                                println!("[TCP-UDP] Failed to write response: {}", e);
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

async fn process_tcp_trojan<S: AsyncRead + AsyncWrite + Unpin>(
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
        println!("[TCP] Incorrect password from {}", peer_addr);
        return Err(anyhow!("Incorrect password"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            handle_tcp_connect(stream, request.addr, request.payload, peer_addr).await
        }
        TrojanCmd::UdpAssociate => {
            handle_tcp_udp_associate(server, stream, request.addr, peer_addr).await
        }
    }
}

// ============ WebSocket 模式处理函数 ============

async fn websocket_to_tcp<S: AsyncWriteExt + Unpin + 'static>(
    mut ws_read: SplitStream<WebSocketStream<S>>,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) -> Result<()> 
where 
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    while let Some(msg) = ws_read.next().await {
        match msg? {
            Message::Binary(data) => {
                tcp_write.write_all(&data).await?;
            }
            Message::Close(_) => break,
            _ => continue,
        }
    }
    Ok(())
}

async fn tcp_to_websocket<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_write: SplitSink<WebSocketStream<S>, Message>,
) -> Result<()> {
    use futures_util::SinkExt;
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = tcp_read.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        ws_write.send(Message::Binary(buf[..n].to_vec())).await?;
    }
    Ok(())
}

async fn handle_ws_udp_associate<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<S>>,
    mut ws_write: SplitSink<WebSocketStream<S>, Message>,
    _bind_addr: socks5::Address,
    client_info: String,
) -> Result<()> {
    use futures_util::{StreamExt, SinkExt};
    
    let socket_key = format!("ws_client_{}_{}", client_info, 
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
        println!("[WS-UDP] Created UDP socket bound to: {}", socket.local_addr()?);
        
        let association = udp::UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    
    let udp_recv_handle: JoinHandle<()> = tokio::spawn(async move {
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
                            
                            if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let result = async {
        loop {
            tokio::select! {
                ws_msg = ws_read.next() => {
                    match ws_msg {
                        Some(Ok(Message::Binary(data))) => {
                            match udp::UdpPacket::decode(&data) {
                                Ok((udp_packet, _)) => {
                                    udp_association.update_activity().await;
                                    
                                    match udp_packet.addr.to_socket_addr().await {
                                        Ok(remote_addr) => {
                                            let _ = udp_association.socket.send_to(&udp_packet.payload, remote_addr).await;
                                        }
                                        Err(_) => {}
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        _ => continue,
                    }
                }
                
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
                            if ws_write.send(Message::Binary(encoded)).await.is_err() {
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

async fn process_websocket_trojan<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<S>>,
    ws_write: SplitSink<WebSocketStream<S>, Message>,
    peer_addr: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let msg = match ws_read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) => return Ok(()),
        Some(Err(e)) => return Err(e.into()),
        _ => return Err(anyhow!("Expected binary message")),
    };

    let (request, _consumed) = TrojanRequest::decode(&msg)?;

    if request.password != server.password {
        println!("[WS] Incorrect password from {}", peer_addr);
        return Err(anyhow!("Incorrect password"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            println!("[WS] Handling TCP CONNECT to {}", request.addr.to_key());
            
            let remote_addr = request.addr.to_socket_addr().await?;
            let remote_stream = TcpStream::connect(remote_addr).await?;

            let (remote_read, mut remote_write) = tokio::io::split(remote_stream);

            if !request.payload.is_empty() {
                remote_write.write_all(&request.payload).await?;
            }

            tokio::select! {
                result = websocket_to_tcp(ws_read, remote_write) => {
                    if let Err(e) = result {
                        println!("[WS] WS to TCP error: {}", e);
                    }
                },
                result = tcp_to_websocket(remote_read, ws_write) => {
                    if let Err(e) = result {
                        println!("[WS] TCP to WS error: {}", e);
                    }
                },
            }
        }
        
        TrojanCmd::UdpAssociate => {
            println!("[WS] Handling UDP ASSOCIATE for {}", request.addr.to_key());
            handle_ws_udp_associate(server, ws_read, ws_write, request.addr, peer_addr.clone()).await?;
        }
    }

    Ok(())
}

// ============ 连接检测与分发 ============
async fn detect_and_handle_connection<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: String,
) -> Result<()> 
where S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    if server.enable_ws {
        let ws_stream = tokio_tungstenite::accept_async(stream).await?;
        let (ws_write, ws_read) = ws_stream.split();
        process_websocket_trojan(server, ws_read, ws_write, peer_addr).await
    } else {
        process_tcp_trojan(server, stream, peer_addr).await
    }
}


fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", cert_path));
    }

    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)?;

    let key = key.ok_or_else(|| anyhow!("No private key found in {}", key_path))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        println!("Server started, listening on {}", server.listener.local_addr()?);
        println!("Mode: {} mode", {
                if server.enable_ws {"websocket"}
                else {"tcp"}
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
                                        detect_and_handle_connection(server_clone, tls_stream, peer_addr.clone()).await
                                    }
                                    Err(e) => {
                                        Err(anyhow!("TLS handshake failed: {}", e))
                                    }
                                }
                            } else {
                                detect_and_handle_connection(server_clone, stream, peer_addr.clone()).await
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

    let tls_acceptor = match (&config.cert, &config.key) {
        (Some(cert_path), Some(key_path)) => {
            println!("Loading TLS certificates from: {}, {}", cert_path, key_path);
            Some(load_tls_config(cert_path, key_path)?)
        }
        (None, None) => {
            println!("No TLS certificates provided, running in plain mode");
            None
        }
        _ => {
            return Err(anyhow!("Both --cert and --key must be provided together, or neither"));
        }
    };

    Ok(Server {
        listener,
        password,
        enable_ws,
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