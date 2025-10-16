use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};

// SOCKS5 地址类型定义
#[derive(Debug, Clone, Copy)]
pub enum _AddressType {
    IPv4 = 1,
    FQDN = 3,
    IPv6 = 4,
}

// SOCKS5 地址表示
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
                addrs
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("域名解析失败: {}", domain))
            }
        }
    }

    // 对于 UDP 会话，键值不直接采用目标地址
    // 可以结合连接信息或生成独立套接字保证唯一性
    pub fn to_association_key(&self, client_info: &str) -> String {
        format!("{}_{}", client_info, self.to_key())
    }

    pub fn to_key(&self) -> String {
        match self {
            Address::IPv4(ip, port) => format!("{}:{}", std::net::Ipv4Addr::from(*ip), port),
            Address::IPv6(ip, port) => format!("[{}]:{}", std::net::Ipv6Addr::from(*ip), port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}
