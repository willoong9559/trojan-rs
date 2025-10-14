mod utils;
mod udp;
mod socks5;

use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use anyhow::{Result, anyhow};

// TLS support
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;

const BUF_SIZE: usize = 8192;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan WS Server")]
struct ServerConfig {
    /// Host address
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port number
    #[arg(long, default_value = "35537")]
    port: String,

    /// Password
    #[arg(long)]
    password: String,

    /// TLS certificate file path (optional)
    #[arg(long)]
    cert: Option<String>,

    /// TLS private key file path (optional)
    #[arg(long)]
    key: Option<String>,
}

// Enum to handle both TLS and non-TLS connections
enum Connection {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Connection {
    fn peer_addr(&self) -> Result<SocketAddr> {
        match self {
            Connection::Plain(stream) => Ok(stream.peer_addr()?),
            Connection::Tls(stream) => Ok(stream.get_ref().0.peer_addr()?),
        }
    }
}

pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56],
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

async fn websocket_to_tcp(
    mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) -> Result<()> {
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

async fn tcp_to_websocket(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_write: SplitSink<WebSocketStream<TcpStream>, Message>,
) -> Result<()> {
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

async fn handle_udp_associate(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
    mut ws_write: SplitSink<WebSocketStream<TcpStream>, Message>,
    bind_addr: socks5::Address,
    client_info: String,
) -> Result<()> {
    println!("Starting UDP Associate mode for client: {}", client_info);
    
    let socket_key = format!("client_{}_{}", client_info, 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());
    
    let udp_association = {
        let mut associations = server.udp_associations.lock().await;
        
        let bind_socket_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 
            0
        );
        
        let socket = UdpSocket::bind(bind_socket_addr).await
            .map_err(|e| anyhow!("Failed to bind UDP socket to {}: {}", bind_socket_addr, e))?;
            
        println!("Created new UDP socket bound to: {} for client: {}", socket.local_addr()?, client_info);
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
                _ = &mut cancel_rx => {
                    println!("UDP receiver task cancelled for socket");
                    break;
                }
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from_addr)) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            *activity_tracker.lock().await = now;
                            
                            if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                                println!("UDP channel closed, stopping receiver");
                                break;
                            }
                        }
                        Err(e) => {
                            println!("UDP recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        println!("UDP receiver task terminated");
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
                                            if let Err(e) = udp_association.socket.send_to(&udp_packet.payload, remote_addr).await {
                                                println!("Failed to send UDP packet to {}: {}", remote_addr, e);
                                            } else {
                                                println!("Forwarded UDP packet to {}", remote_addr);
                                            }
                                        }
                                        Err(e) => {
                                            println!("Failed to resolve remote address: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to decode UDP packet: {}", e);
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            println!("WebSocket closed");
                            break;
                        }
                        Some(Err(e)) => {
                            println!("WebSocket error: {}", e);
                            break;
                        }
                        None => {
                            println!("WebSocket stream ended");
                            break;
                        }
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
                            if let Err(e) = ws_write.send(Message::Binary(encoded)).await {
                                println!("Failed to send UDP packet back to WebSocket: {}", e);
                                break;
                            } else {
                                println!("Sent UDP packet back to WebSocket client from {}", from_addr);
                            }
                        }
                        None => {
                            println!("UDP channel closed");
                            break;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    println!("Starting cleanup for UDP association: {}", socket_key);
    let _ = cancel_tx.send(());
    
    match tokio::time::timeout(std::time::Duration::from_secs(5), udp_recv_handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                println!("UDP receiver task join error: {}", e);
            } else {
                println!("UDP receiver task successfully terminated");
            }
        }
        Err(_) => {
            println!("Warning: UDP receiver task did not terminate within timeout");
        }
    }
    
    drop(udp_tx);
    drop(udp_rx);
    
    {
        let mut associations = server.udp_associations.lock().await;
        if associations.remove(&socket_key).is_some() {
            println!("Successfully removed UDP association: {} for client: {}", socket_key, client_info);
        } else {
            println!("Warning: UDP association {} was already removed", socket_key);
        }
    }

    println!("Cleanup complete for UDP association: {}", socket_key);
    result
}

async fn handle_websocket(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    let peer_addr = stream.peer_addr().ok().map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    let ws_stream = accept_async(stream).await?;
    println!("WebSocket connection established from {}", peer_addr);

    let (ws_write, mut ws_read) = ws_stream.split();

    let msg = match ws_read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) => return Ok(()),
        Some(Err(e)) => return Err(e.into()),
        _ => return Err(anyhow!("Expected binary message")),
    };

    let (request, _consumed) = TrojanRequest::decode(&msg)?;

    let expected_password: [u8; 56] = server.password;
    if request.password != expected_password {
        println!("Incorrect password from WebSocket client");
        return Err(anyhow!("Incorrect password"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            println!("Handling TCP CONNECT command to {}", request.addr.to_key());
            
            let remote_addr = request.addr.to_socket_addr().await?;
            let remote_stream = TcpStream::connect(remote_addr).await?;
            println!("Connected to remote server: {}", remote_addr);

            let (remote_read, mut remote_write) = tokio::io::split(remote_stream);

            if !request.payload.is_empty() {
                if let Err(e) = remote_write.write_all(&request.payload).await {
                    println!("Failed to write initial payload: {}", e);
                    return Err(e.into());
                }
                println!("Wrote initial payload of {} bytes", request.payload.len());
            }

            println!("Starting TCP bidirectional forwarding");

            tokio::select! {
                result = websocket_to_tcp(ws_read, remote_write) => {
                    if let Err(e) = result {
                        println!("WebSocket to TCP forwarding error: {}", e);
                    } else {
                        println!("WebSocket to TCP forwarding completed");
                    }
                },
                result = tcp_to_websocket(remote_read, ws_write) => {
                    if let Err(e) = result {
                        println!("TCP to WebSocket forwarding error: {}", e);
                    } else {
                        println!("TCP to WebSocket forwarding completed");
                    }
                },
            }
            
            println!("TCP connection closed for {}", peer_addr);
        }
        
        TrojanCmd::UdpAssociate => {
            println!("Handling UDP ASSOCIATE command for target: {}", request.addr.to_key());
            
            if let Err(e) = handle_udp_associate(server, ws_read, ws_write, request.addr, peer_addr.clone()).await {
                println!("UDP Associate error for {}: {}", peer_addr, e);
                return Err(e);
            }
            
            println!("UDP Associate session ended for {}", peer_addr);
        }
    }

    Ok(())
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
        
        if server.tls_acceptor.is_some() {
            println!("TLS enabled");
        } else {
            println!("TLS disabled (running in plain mode)");
        }

        let server_cleanup = Arc::clone(&server);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(udp::UDP_TIMEOUT / 2));
            loop {
                interval.tick().await;
                let mut associations = server_cleanup.udp_associations.lock().await;
                let mut keys_to_remove = Vec::new();
                
                for (key, association) in associations.iter() {
                    if association.is_inactive(udp::UDP_TIMEOUT).await {
                        println!("Marking inactive UDP association for removal: {}", key);
                        keys_to_remove.push(key.clone());
                    }
                }
                
                for key in keys_to_remove {
                    if associations.remove(&key).is_some() {
                        println!("Removed inactive UDP association: {}", key);
                    }
                }
                
                if !associations.is_empty() {
                    println!("Active UDP associations: {}", associations.len());
                    for (key, association) in associations.iter() {
                        let client_count = association.get_client_count().await;
                        let last_activity = association.get_last_activity().await;
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        println!("  {}: {} clients, last activity {} seconds ago", 
                                key, client_count, now - last_activity);
                    }
                }
            }
        });

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    println!("New connection from: {}", addr);
                    let server_clone = Arc::clone(&server);
                    tokio::spawn(async move {
                        if let Err(e) = async {
                            let final_stream = if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                let tls_stream = tls_acceptor.accept(stream).await?;
                                let (tx, rx) = tokio::io::split(tls_stream);
                                let tcp_stream = TcpStream::connect("0.0.0.0:0").await?;
                                tcp_stream
                            } else {
                                stream
                            };
                            
                            handle_websocket(server_clone, final_stream).await
                        }.await {
                            println!("Connection error from {}: {}", addr, e);
                        } else {
                            println!("Connection from {} closed successfully", addr);
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

pub async fn build_server(config: ServerConfig) -> Result<Server> {
    let addr: String = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(addr).await?;

    let password = utils::password_to_hex(&config.password);

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
        udp_associations: Arc::new(Mutex::new(HashMap::new())),
        tls_acceptor,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::parse();
    let server = build_server(config).await?;
    server.run().await
}