use crate::socks5;

use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

pub const UDP_TIMEOUT: u64 = 60; // UDP 会话超时时间（秒）

// UDP 会话信息
#[derive(Debug, Clone)]
pub struct UdpAssociation {
    pub socket: Arc<UdpSocket>,
    pub last_activity: Arc<Mutex<u64>>, // 最近活动时间（Unix 时间戳）
    pub client_count: Arc<Mutex<u32>>,  // 活跃客户端数量
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

        // 若无活跃客户端且超过超时时间则需要清理
        client_count == 0 && (now - last_activity) > timeout_secs
    }
}

// Trojan UDP Associate 使用的 UDP 数据报
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: socks5::Address,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 4 {
            return Err(anyhow!("缓冲区长度不足"));
        }

        let mut cursor = 0;
        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                // IPv4
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("缓冲区长度不足（IPv4 地址）"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv4(ip, port)
            }
            3 => {
                // Domain
                if buf.len() <= cursor {
                    return Err(anyhow!("缓冲区长度不足（域名长度）"));
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Err(anyhow!("缓冲区长度不足（域名）"));
                }
                let domain = String::from_utf8(buf[cursor..cursor + domain_len].to_vec())?;
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::Domain(domain, port)
            }
            4 => {
                // IPv6
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("缓冲区长度不足（IPv6 地址）"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("不支持的地址类型")),
        };

        // Read length
        if buf.len() < cursor + 2 {
            return Err(anyhow!("缓冲区长度不足（数据长度）"));
        }
        let length = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        // Read CRLF
        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("CRLF 结尾格式不正确"));
        }
        cursor += 2;

        // Read payload
        if buf.len() < cursor + length as usize {
            return Err(anyhow!("缓冲区长度不足（负载数据）"));
        }
        let payload = buf[cursor..cursor + length as usize].to_vec();
        cursor += length as usize;

        Ok((
            UdpPacket {
                addr,
                length,
                payload,
            },
            cursor,
        ))
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
