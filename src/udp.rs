use crate::socks5;

use tokio::net::{UdpSocket};
use tokio::sync::{Mutex};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Result, anyhow};
use bytes::Bytes;

pub const UDP_TIMEOUT: u64 = 300; // UDP association timeout in seconds;

// UDP Association info
#[derive(Debug, Clone)]
pub struct UdpAssociation {
    pub socket: Arc<UdpSocket>,
    pub last_activity: Arc<Mutex<u64>>, // Unix timestamp
    pub client_count: Arc<Mutex<u32>>,  // Number of active clients using this socket
}

impl UdpAssociation {
   pub fn new(socket: UdpSocket) -> Self {
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
    
    pub async fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        *self.last_activity.lock().await = now;
    }
    
    pub async fn increment_clients(&self) {
        *self.client_count.lock().await += 1;
    }
    
    pub async fn decrement_clients(&self) {
        let mut count = self.client_count.lock().await;
        if *count > 0 {
            *count -= 1;
        }
    }
    
    pub async fn get_client_count(&self) -> u32 {
        *self.client_count.lock().await
    }
    
    pub async fn get_last_activity(&self) -> u64 {
        *self.last_activity.lock().await
    }
    
    pub async fn is_inactive(&self, timeout_secs: u64) -> bool {
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
        let mut buf = Vec::new();

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