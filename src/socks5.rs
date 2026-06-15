use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;

/// Order resolved addresses for happy eyeballs: IPv6, IPv4, IPv6, IPv4, ...
/// so the first IPv4 attempt starts soon instead of after every AAAA record.
fn sort_addrs_for_happy_eyeballs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v6_addrs = Vec::new();
    let mut v4_addrs = Vec::new();

    for addr in addrs {
        match addr {
            SocketAddr::V6(_) => v6_addrs.push(addr),
            SocketAddr::V4(_) => v4_addrs.push(addr),
        }
    }

    let mut result = Vec::with_capacity(v6_addrs.len() + v4_addrs.len());
    let max_len = v6_addrs.len().max(v4_addrs.len());
    for i in 0..max_len {
        if i < v6_addrs.len() {
            result.push(v6_addrs[i]);
        }
        if i < v4_addrs.len() {
            result.push(v4_addrs[i]);
        }
    }
    result
}

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

    pub async fn resolve_socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Address::IPv4(ip, port) => {
                let addr = IpAddr::V4(std::net::Ipv4Addr::from(*ip));
                Ok(vec![SocketAddr::new(addr, *port)])
            }
            Address::IPv6(ip, port) => {
                let addr = IpAddr::V6(std::net::Ipv6Addr::from(*ip));
                Ok(vec![SocketAddr::new(addr, *port)])
            }
            Address::Domain(domain, port) => {
                let addrs = tokio::time::timeout(
                    tokio::time::Duration::from_secs(DNS_RESOLVE_TIMEOUT_SECS),
                    tokio::net::lookup_host((domain.as_str(), *port)),
                )
                .await
                .map_err(|_| {
                    anyhow!(
                        "DNS resolution timeout after {} seconds",
                        DNS_RESOLVE_TIMEOUT_SECS
                    )
                })??;
                let addrs: Vec<SocketAddr> = addrs.collect();
                if addrs.is_empty() {
                    return Err(anyhow!("Failed to resolve domain: {}", domain));
                }
                Ok(sort_addrs_for_happy_eyeballs(addrs))
            }
        }
    }

    pub async fn to_socket_addr(&self) -> Result<SocketAddr> {
        self.resolve_socket_addrs()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Failed to resolve address"))
    }

    // For UDP associations, we don't use the target address as the key
    // Instead, we could use connection info or just create unique sockets
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
