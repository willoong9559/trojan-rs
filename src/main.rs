mod utils;

use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_tungstenite::{accept_async, WebSocketStream};
use tokio_tungstenite::tungstenite::{Message, Result as WsResult};
use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use sha2::{Sha224, Digest};
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};

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
}

#[derive(Debug)]
pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56], // Hex SHA224 hash
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

// Handle WebSocket connection
async fn handle_websocket(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    let ws_stream = accept_async(stream).await?;
    println!("WebSocket connection established");

    let (ws_write, mut ws_read) = ws_stream.split();

    // Read initial message containing Trojan request
    let msg = match ws_read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) => return Ok(()),
        Some(Err(e)) => return Err(e.into()),
        _ => return Err(anyhow!("Expected binary message")),
    };

    // Parse Trojan request
    let (request, consumed) = TrojanRequest::decode(&msg)?;

    // Verify password
    let expected_password: [u8; 56] = server.password;
    // let expected_password: [u8; 56] = password_to_hex(&server.password);
    if request.password != expected_password {
        println!("Incorrect password from WebSocket client");
        return Err(anyhow!("Incorrect password"));
    }

    // Only support CONNECT for WebSocket
    if request.cmd != TrojanCmd::Connect {
        println!("Only TCP CONNECT supported over WebSocket");
        return Err(anyhow!("Only TCP CONNECT supported"));
    }

    // Connect to remote server
    let remote_addr = request.addr.to_socket_addr().await?;
    let remote_stream = TcpStream::connect(remote_addr).await?;

    // Write any payload data from the initial request
    if !request.payload.is_empty() {
        let (remote_read, mut remote_write) = tokio::io::split(remote_stream);
        remote_write.write_all(&request.payload).await?;

        println!("Starting WebSocket bidirectional forwarding");

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
    } else {
        let (remote_read, remote_write) = tokio::io::split(remote_stream);

        println!("Starting WebSocket bidirectional forwarding");

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

    Ok(())
}

// Main server implementation
impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        println!("Server started, listening on {}", server.listener.local_addr()?);

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
    })
}

// usage
#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::parse();

    let server = build_server(config).await?;
    server.run().await
}
