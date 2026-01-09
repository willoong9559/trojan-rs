use std::net::{IpAddr, SocketAddr};
use anyhow::{Result, anyhow};

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;

// SOCKS5 Address types
#[derive(Debug, Clone, Copy)]
pub enum _AddressType {
    IPv4 = 1,
    FQDN = 3,
    IPv6 = 4,
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
                let addrs = tokio::time::timeout(
                    tokio::time::Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
                    tokio::net::lookup_host((domain.as_str(), *port)),
                )
                .await
                .map_err(|_| anyhow!("DNS resolution timeout after {} seconds", DNS_RESOLVE_TIMEOUT_SECS))??;
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