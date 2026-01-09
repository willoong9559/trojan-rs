use crate::socks5;
use crate::logger::log;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use bytes::Bytes;

pub const UDP_TIMEOUT: u64 = 300; // UDP association timeout in seconds;

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