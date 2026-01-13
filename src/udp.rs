use crate::socks5;
use crate::logger::log;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};

pub const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;

// UDP 相关常量
const BUF_SIZE: usize = 4 * 1024;
const UDP_CHANNEL_BUFFER_SIZE: usize = 64;
const TCP_WRITE_CHANNEL_BUFFER_SIZE: usize = 256;
const CLEANUP_TIMEOUT_SECS: u64 = 5;

// UDP Association info
#[derive(Debug, Clone)]
pub struct UdpAssociation {
    pub socket: Arc<UdpSocket>,
    last_activity: Arc<AtomicU64>,
    created_at: Instant,
}

impl UdpAssociation {
    pub fn new(socket: UdpSocket) -> Self {
        let now = Self::current_timestamp();
        
        Self {
            socket: Arc::new(socket),
            last_activity: Arc::new(AtomicU64::new(now)),
            created_at: Instant::now(),
        }
    }
    
    #[inline]
    pub fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    #[inline]
    pub fn update_activity(&self) {
        self.last_activity.store(Self::current_timestamp(), Ordering::Relaxed);
    }
    
    #[inline]
    pub fn get_last_activity(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }
    
    pub fn is_inactive(&self, timeout_secs: u64) -> bool {
        let now = Self::current_timestamp();
        let last_activity = self.get_last_activity();
        (now - last_activity) > timeout_secs
    }
    
    #[inline]
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

// UDP Packet for Trojan UDP Associate
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: socks5::Address,
    pub length: u16,
    pub payload: Bytes,
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
                socks5::Address::IPv4(ip, port)
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
                let domain = std::str::from_utf8(&buf[cursor..cursor + domain_len])
                    .map_err(|e| anyhow!("Invalid UTF-8 domain: {}", e))?
                    .to_string();
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::Domain(domain, port)
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
                socks5::Address::IPv6(ip, port)
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

        if buf.len() < cursor + length as usize {
            return Err(anyhow!("Buffer too small for payload"));
        }
        let payload = Bytes::copy_from_slice(&buf[cursor..cursor + length as usize]);
        cursor += length as usize;

        Ok((UdpPacket {
            addr,
            length,
            payload,
        }, cursor))
    }

    pub fn encode(&self) -> Vec<u8> {
        let addr_size = match &self.addr {
            socks5::Address::IPv4(_, _) => 1 + 4 + 2, // type + ip + port
            socks5::Address::Domain(domain, _) => 1 + 1 + domain.len() + 2, // type + len + domain + port
            socks5::Address::IPv6(_, _) => 1 + 16 + 2, // type + ip + port
        };
        let total_size = addr_size + 2 + 2 + self.payload.len(); // addr + length + CRLF + payload
        
        let mut buf = Vec::with_capacity(total_size);

        match &self.addr {
            socks5::Address::IPv4(ip, port) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            socks5::Address::Domain(domain, port) => {
                buf.push(3); // Domain
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            socks5::Address::IPv6(ip, port) => {
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

// UDP清理任务，定期清理不活跃的UDP association
pub fn start_cleanup_task(
    associations: Arc<Mutex<HashMap<String, UdpAssociation>>>
) {
    tokio::spawn(async move {
        const CLEANUP_INTERVAL_SECS: u64 = UDP_TIMEOUT / 2;
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)
        );
        interval.tick().await;
        
        loop {
            interval.tick().await;
            
            let associations_to_check: Vec<(String, UdpAssociation)> = {
                let assocs = associations.lock().await;
                assocs.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            };
            
            let mut keys_to_remove = Vec::new();
            for (key, association) in associations_to_check {
                if association.is_inactive(UDP_TIMEOUT) {
                    keys_to_remove.push(key);
                }
            }
            
            if !keys_to_remove.is_empty() {
                let mut assocs = associations.lock().await;
                let removed_count = keys_to_remove.len();
                for key in keys_to_remove {
                    assocs.remove(&key);
                }
                log::debug!(
                    removed = removed_count,
                    remaining = assocs.len(),
                    "Cleaned up inactive UDP associations"
                );
            }
        }
    });
}

// 处理 UDP Associate 请求
pub async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    udp_associations: Arc<Mutex<HashMap<String, UdpAssociation>>>,
    client_stream: S,
    _bind_addr: socks5::Address,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, "Starting UDP associate");
    
    // 生成唯一的socket key
    let socket_key = format!("client_{}_{}", peer_addr, 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());
    
    let udp_association = {
        let bind_socket_addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 
            0
        );
        let socket = UdpSocket::bind(bind_socket_addr).await?;
        let association = UdpAssociation::new(socket);
        
        let mut associations = udp_associations.lock().await;
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (mut client_read, client_write) = tokio::io::split(client_stream);
    
    let (udp_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Bytes)>(UDP_CHANNEL_BUFFER_SIZE);
    let (tcp_write_tx, mut tcp_write_rx) = mpsc::channel::<Vec<u8>>(TCP_WRITE_CHANNEL_BUFFER_SIZE);
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let association_clone = udp_association.clone();
    
    let udp_recv_handle = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(BUF_SIZE);
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    break;
                }
                result = {
                    buf.clear();
                    if buf.capacity() < BUF_SIZE {
                        buf.reserve(BUF_SIZE - buf.capacity());
                    }
                    buf.resize(BUF_SIZE, 0);
                    socket_clone.recv_from(&mut buf[..])
                } => {
                    match result {
                        Ok((len, from_addr)) => {
                            association_clone.update_activity();
                            
                            buf.truncate(len);
                            
                            let data = buf.split_to(len).freeze();
                            
                            match udp_tx.try_send((from_addr, data)) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!("UDP channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break;
                                }
                            }
                            
                            if buf.capacity() > BUF_SIZE * 2 {
                                buf = BytesMut::with_capacity(BUF_SIZE);
                            }
                        }
                        Err(e) => {
                            log::debug!("UDP socket recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });
    
    let peer_addr_for_write = peer_addr.clone();
    let tcp_write_handle = tokio::spawn(async move {
        let mut client_write = client_write;
        while let Some(encoded) = tcp_write_rx.recv().await {
            let mut written = 0;
            while written < encoded.len() {
                match client_write.write(&encoded[written..]).await {
                    Ok(0) => {
                        log::debug!(peer = %peer_addr_for_write, "TCP connection closed while writing UDP response, dropping UDP");
                        return;
                    }
                    Ok(n) => {
                        written += n;
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr_for_write, error = %e, "Error writing UDP response to client, dropping UDP");
                        return;
                    }
                }
            }
        }
    });

    let result = async {
        let mut read_buf = vec![0u8; BUF_SIZE];
        let mut buffer = BytesMut::with_capacity(BUF_SIZE);
        'main_loop: loop {
            tokio::select! {
                read_result = client_read.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => {
                            break 'main_loop;
                        }
                        Ok(n) => {
                            buffer.extend_from_slice(&read_buf[..n]);
                            
                            loop {
                                match UdpPacket::decode(&buffer) {
                                    Ok((udp_packet, consumed)) => {
                                        let _ = buffer.split_to(consumed);
                                        
                                        udp_association.update_activity();
                                        
                                        match udp_packet.addr.to_socket_addr().await {
                                            Ok(remote_addr) => {
                                                if let Err(e) = udp_association.socket
                                                    .send_to(&udp_packet.payload, remote_addr).await {
                                                    log::debug!(peer = %peer_addr, error = %e, "Failed to send UDP packet");
                                                }
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, error = %e, "Failed to resolve UDP target address");
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!(peer = %peer_addr, error = %e, "Error reading from client stream");
                            break 'main_loop;
                        }
                    }
                }
                
                packet = udp_rx.recv() => {
                    match packet {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
                            };
                            
                            let udp_packet = UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };
                            
                            let encoded = udp_packet.encode();
                            match tcp_write_tx.try_send(encoded) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!(peer = %peer_addr, "TCP write channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break 'main_loop;
                                }
                            }
                        }
                        None => {
                            break 'main_loop;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    drop(tcp_write_tx);
    
    let _ = cancel_tx.send(());
    
    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        tcp_write_handle
    ).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "TCP write task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "TCP write task cleanup timeout"
            );
        }
    }
    
    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        udp_recv_handle
    ).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "UDP receive task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "UDP receive task cleanup timeout"
            );
        }
    }
    
    {
        let mut associations = udp_associations.lock().await;
        associations.remove(&socket_key);
    }

    result
}