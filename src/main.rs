mod utils;

use clap::Parser;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, WebSocketStream};
use tokio_tungstenite::tungstenite::{Message, Result as WsResult};
use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use anyhow::{Result, anyhow};

const BUF_SIZE: usize = 8192;
const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;

// UDP Association info
#[derive(Debug, Clone)]
struct UdpAssociation {
    socket: Arc<UdpSocket>,
    last_activity: Arc<Mutex<u64>>, // Unix timestamp
    client_count: Arc<Mutex<u32>>,  // Number of active clients using this socket
}

impl UdpAssociation {
    fn new(socket: UdpSocket) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            socket: Arc::new(socket),
            last_activity: Arc::new(Mutex::new(now)),
            client_count: Arc::new(Mutex::new(1)),
        }
    }
    
    async fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        *self.last_activity.lock().await = now;
    }
    
    async fn increment_clients(&self) {
        *self.client_count.lock().await += 1;
    }
    
    async fn decrement_clients(&self) {
        let mut count = self.client_count.lock().await;
        if *count > 0 {
            *count -= 1;
        }
    }
    
    async fn get_client_count(&self) -> u32 {
        *self.client_count.lock().await
    }
    
    async fn get_last_activity(&self) -> u64 {
        *self.last_activity.lock().await
    }
    
    async fn is_inactive(&self, timeout_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let last_activity = self.get_last_activity().await;
        let client_count = self.get_client_count().await;
        
        // Clean up if no clients and inactive for timeout period
        client_count == 0 && (now - last_activity) > timeout_secs
    }
}

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
}

#[derive(Debug)]
pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56], // Hex SHA224 hash
    pub udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
}

// Error codes
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Ok = 0,
    ErrRead = 1,
    ErrWrite = 2,
    ErrResolve = 3,
    MoreData = 4,
}

// SOCKS5 Address types
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    IPv4 = 1,
    FQDN = 3,
    IPv6 = 4,
}

// Trojan Command types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrojanCmd {
    Connect = 1,
    UdpAssociate = 3,
}

// SOCKS5 Address
#[derive(Debug, Clone)]
pub enum Address {
    IPv4([u8; 4], u16),
    IPv6([u8; 16], u16),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(_, port) => *port,
            Address::IPv6(_, port) => *port,
            Address::Domain(_, port) => *port,
        }
    }

    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        match self {
            Address::IPv4(ip, port) => {
                let addr = IpAddr::V4(std::net::Ipv4Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::IPv6(ip, port) => {
                let addr = IpAddr::V6(std::net::Ipv6Addr::from(*ip));
                Ok(SocketAddr::new(addr, *port))
            }
            Address::Domain(domain, port) => {
                let addrs = tokio::net::lookup_host((domain.as_str(), *port)).await?;
                addrs.into_iter().next()
                    .ok_or_else(|| anyhow!("Failed to resolve domain: {}", domain))
            }
        }
    }

    // For UDP associations, we don't use the target address as the key
    // Instead, we could use connection info or just create unique sockets
    pub fn to_association_key(&self, client_info: &str) -> String {
        format!("{}_{}", client_info, self.to_key())
    }
    
    pub fn to_key(&self) -> String {
        match self {
            Address::IPv4(ip, port) => format!("{}:{}", 
                std::net::Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => format!("[{}]:{}", 
                std::net::Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

// Trojan Request
#[derive(Debug)]
pub struct TrojanRequest {
    pub password: [u8; 56], // hex password
    pub cmd: TrojanCmd,
    pub addr: Address,
    pub payload: Vec<u8>,
}

impl TrojanRequest {
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 59 { // min: 56 + 1 + 1 + 1 (password + cmd + atyp + minimal addr)
            return Err(anyhow!("Buffer too small"));
        }

        let mut cursor = 0;

        // Read password (56 bytes hex)
        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        // Read CRLF after password
        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after password"));
        }
        cursor += 2;

        // Read command
        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("Invalid command")),
        };
        cursor += 1;

        // Read address type
        let atyp = buf[cursor];
        cursor += 1;

        // Read address based on type
        let addr = match atyp {
            1 => { // IPv4
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("Buffer too small for IPv4"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Address::IPv4(ip, port)
            }
            3 => { // Domain
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
                Address::Domain(domain, port)
            }
            4 => { // IPv6
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("Buffer too small for IPv6"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("Invalid address type")),
        };

        // Read CRLF after address
        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF after address"));
        }
        cursor += 2;

        // Remaining data is payload
        let payload = buf[cursor..].to_vec();

        Ok((TrojanRequest {
            password,
            cmd,
            addr,
            payload,
        }, cursor))
    }
}

// UDP Packet for Trojan UDP Associate
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: Address,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 4 {
            return Err(anyhow!("Buffer too small"));
        }

        let mut cursor = 0;
        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => { // IPv4
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("Buffer too small for IPv4"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Address::IPv4(ip, port)
            }
            3 => { // Domain
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
                Address::Domain(domain, port)
            }
            4 => { // IPv6
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("Buffer too small for IPv6"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("Invalid address type")),
        };

        // Read length
        if buf.len() < cursor + 2 {
            return Err(anyhow!("Buffer too small for length"));
        }
        let length = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        // Read CRLF
        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("Invalid CRLF"));
        }
        cursor += 2;

        // Read payload
        if buf.len() < cursor + length as usize {
            return Err(anyhow!("Buffer too small for payload"));
        }
        let payload = buf[cursor..cursor + length as usize].to_vec();
        cursor += length as usize;

        Ok((UdpPacket {
            addr,
            length,
            payload,
        }, cursor))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match &self.addr {
            Address::IPv4(ip, port) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::Domain(domain, port) => {
                buf.push(3); // Domain
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            Address::IPv6(ip, port) => {
                buf.push(4); // IPv6
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.payload);

        buf
    }
}

// WebSocket to TCP forwarding
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

// TCP to WebSocket forwarding
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

// Handle UDP Associate over WebSocket
async fn handle_udp_associate(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<TcpStream>>,
    mut ws_write: SplitSink<WebSocketStream<TcpStream>, Message>,
    bind_addr: Address,
    client_info: String,
) -> Result<()> {
    println!("Starting UDP Associate mode for client: {}", client_info);
    
    // Create a unique key for this client's UDP association
    // We create separate sockets per client to avoid conflicts
    let socket_key = format!("client_{}_{}", client_info, 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());
    
    let udp_association = {
        let mut associations = server.udp_associations.lock().await;
        
        // Always create a new UDP socket for each UDP Associate request
        // This avoids binding conflicts and provides better isolation
        // For UDP Associate, we should bind to a local address, not the target address
        // The bind_addr from the client is the target they want to associate with,
        // but we need to create a local UDP socket to forward traffic
        let bind_socket_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 
            0  // Let OS choose an available port
        );
        
        let socket = UdpSocket::bind(bind_socket_addr).await
            .map_err(|e| anyhow!("Failed to bind UDP socket to {}: {}", bind_socket_addr, e))?;
            
        println!("Created new UDP socket bound to: {} for client: {}", socket.local_addr()?, client_info);
        let association = UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    // Create channels for UDP packet forwarding
    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

    // Spawn UDP receiver task
    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    
    tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            match socket_clone.recv_from(&mut buf).await {
                Ok((len, from_addr)) => {
                    // Update activity time
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    *activity_tracker.lock().await = now;
                    
                    if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    println!("UDP recv error: {}", e);
                    break;
                }
            }
        }
    });

    let result = async {
        loop {
            tokio::select! {
                // Handle incoming WebSocket messages (UDP packets from client)
                ws_msg = ws_read.next() => {
                    match ws_msg {
                        Some(Ok(Message::Binary(data))) => {
                            match UdpPacket::decode(&data) {
                                Ok((udp_packet, _)) => {
                                    // Update activity
                                    udp_association.update_activity().await;
                                    
                                    // Forward UDP packet to remote address
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
                        None => break,
                        _ => continue,
                    }
                }
                
                // Handle incoming UDP packets (from remote servers)
                udp_msg = udp_rx.recv() => {
                    if let Some((from_addr, data)) = udp_msg {
                        // Update activity (already updated in UDP receiver task)
                        
                        // Convert SocketAddr back to Address
                        let addr = match from_addr {
                            SocketAddr::V4(v4) => Address::IPv4(v4.ip().octets(), v4.port()),
                            SocketAddr::V6(v6) => Address::IPv6(v6.ip().octets(), v6.port()),
                        };
                        
                        // Create UDP packet
                        let udp_packet = UdpPacket {
                            addr,
                            length: data.len() as u16,
                            payload: data,
                        };
                        
                        // Send back to WebSocket client
                        let encoded = udp_packet.encode();
                        if let Err(e) = ws_write.send(Message::Binary(encoded)).await {
                            println!("Failed to send UDP packet back to WebSocket: {}", e);
                            break;
                        } else {
                            println!("Sent UDP packet back to WebSocket client from {}", from_addr);
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    // Cleanup: remove this association when connection ends
    {
        let mut associations = server.udp_associations.lock().await;
        associations.remove(&socket_key);
        println!("Cleaned up UDP association: {} for client: {}", socket_key, client_info);
    }

    result
}

// Handle WebSocket connection
async fn handle_websocket(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    let peer_addr = stream.peer_addr().ok().map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string());
    let ws_stream = accept_async(stream).await?;
    println!("WebSocket connection established from {}", peer_addr);

    let (ws_write, mut ws_read) = ws_stream.split();

    // Read initial message containing Trojan request
    let msg = match ws_read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) => return Ok(()),
        Some(Err(e)) => return Err(e.into()),
        _ => return Err(anyhow!("Expected binary message")),
    };

    // Parse Trojan request
    let (request, _consumed) = TrojanRequest::decode(&msg)?;

    // Verify password
    let expected_password: [u8; 56] = server.password;
    if request.password != expected_password {
        println!("Incorrect password from WebSocket client");
        return Err(anyhow!("Incorrect password"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            println!("Handling TCP CONNECT command");
            
            // Connect to remote server
            let remote_addr = request.addr.to_socket_addr().await?;
            let remote_stream = TcpStream::connect(remote_addr).await?;

            // Write any payload data from the initial request
            if !request.payload.is_empty() {
                let (remote_read, mut remote_write) = tokio::io::split(remote_stream);
                remote_write.write_all(&request.payload).await?;

                println!("Starting TCP bidirectional forwarding");

                // Start bidirectional forwarding
                tokio::select! {
                    result = websocket_to_tcp(ws_read, remote_write) => {
                        if let Err(e) = result {
                            println!("WebSocket to TCP forwarding error: {}", e);
                        }
                    },
                    result = tcp_to_websocket(remote_read, ws_write) => {
                        if let Err(e) = result {
                            println!("TCP to WebSocket forwarding error: {}", e);
                        }
                    },
                }

            } else {
                let (remote_read, remote_write) = tokio::io::split(remote_stream);

                println!("Starting TCP bidirectional forwarding");

                // Start bidirectional forwarding
                tokio::select! {
                    result = websocket_to_tcp(ws_read, remote_write) => {
                        if let Err(e) = result {
                            println!("WebSocket to TCP forwarding error: {}", e);
                        }
                    }
                    result = tcp_to_websocket(remote_read, ws_write) => {
                        if let Err(e) = result {
                            println!("TCP to WebSocket forwarding error: {}", e);
                        }
                    }
                }
            }
        }
        
        TrojanCmd::UdpAssociate => {
            println!("Handling UDP ASSOCIATE command for target: {}", request.addr.to_key());
            
            // Handle UDP Associate - pass client info for unique socket creation
            if let Err(e) = handle_udp_associate(server, ws_read, ws_write, request.addr, peer_addr).await {
                println!("UDP Associate error: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}

// Main server implementation
impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        println!("Server started, listening on {}", server.listener.local_addr()?);

        // Cleanup task for UDP associations (remove inactive ones periodically)
        let server_cleanup = Arc::clone(&server);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(UDP_TIMEOUT / 2));
            loop {
                interval.tick().await;
                let mut associations = server_cleanup.udp_associations.lock().await;
                let mut keys_to_remove = Vec::new();
                
                for (key, association) in associations.iter() {
                    if association.is_inactive(UDP_TIMEOUT).await {
                        println!("Cleaning up inactive UDP association: {}", key);
                        keys_to_remove.push(key.clone());
                    }
                }
                
                // Remove inactive associations
                for key in keys_to_remove {
                    associations.remove(&key);
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
                        if let Err(e) = handle_websocket(server_clone, stream).await {
                            println!("Connection error: {}", e);
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

// Build server from config
pub async fn build_server(config: ServerConfig) -> Result<Server> {
    let addr: String = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(addr).await?;

    let password = utils::password_to_hex(&config.password);

    Ok(Server {
        listener,
        password,
        udp_associations: Arc::new(Mutex::new(HashMap::new())),
    })
}

// usage
#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::parse();

    let server = build_server(config).await?;
    server.run().await
}
