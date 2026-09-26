use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const DNS_RESOLVE_TIMEOUT_SECS: u64 = 10;
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const DNS_CACHE_MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey {
    domain: String,
    port: u16,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addrs: Vec<SocketAddr>,
    expires_at: Instant,
    last_used: Instant,
}

struct DnsCache {
    entries: HashMap<DnsCacheKey, DnsCacheEntry>,
    max_entries: usize,
}

impl DnsCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    fn get(&mut self, key: &DnsCacheKey, now: Instant) -> Option<Vec<SocketAddr>> {
        if let Some(entry) = self.entries.get_mut(key) {
            if entry.expires_at > now {
                entry.last_used = now;
                return Some(entry.addrs.clone());
            }
        }

        self.entries.remove(key);
        None
    }

    fn insert(&mut self, key: DnsCacheKey, addrs: Vec<SocketAddr>, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);

        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            key,
            DnsCacheEntry {
                addrs,
                expires_at: now + DNS_CACHE_TTL,
                last_used: now,
            },
        );
    }
}

static DNS_CACHE: OnceLock<Mutex<DnsCache>> = OnceLock::new();

fn dns_cache() -> &'static Mutex<DnsCache> {
    DNS_CACHE.get_or_init(|| Mutex::new(DnsCache::new(DNS_CACHE_MAX_ENTRIES)))
}

fn dns_cache_key(domain: &str, port: u16) -> DnsCacheKey {
    DnsCacheKey {
        // DNS host names are case-insensitive, so equivalent requests share an entry.
        domain: domain.to_ascii_lowercase(),
        port,
    }
}

fn cached_addrs(key: &DnsCacheKey) -> Option<Vec<SocketAddr>> {
    let mut cache = dns_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.get(key, Instant::now())
}

fn cache_addrs(key: DnsCacheKey, addrs: Vec<SocketAddr>) {
    let mut cache = dns_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.insert(key, addrs, Instant::now());
}

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
                let cache_key = dns_cache_key(domain, *port);
                if let Some(addrs) = cached_addrs(&cache_key) {
                    return Ok(addrs);
                }

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
                let addrs = sort_addrs_for_happy_eyeballs(addrs);
                cache_addrs(cache_key, addrs.clone());
                Ok(addrs)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(domain: &str) -> DnsCacheKey {
        dns_cache_key(domain, 443)
    }

    #[test]
    fn dns_cache_returns_unexpired_entries_case_insensitively() {
        let now = Instant::now();
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let mut cache = DnsCache::new(2);
        cache.insert(key("Example.COM"), vec![address], now);

        assert_eq!(cache.get(&key("example.com"), now), Some(vec![address]));
    }

    #[test]
    fn dns_cache_discards_expired_entries() {
        let now = Instant::now();
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let mut cache = DnsCache::new(2);
        let cache_key = key("example.com");
        cache.insert(cache_key.clone(), vec![address], now);

        assert_eq!(cache.get(&cache_key, now + DNS_CACHE_TTL), None);
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn dns_cache_evicts_least_recently_used_entry_when_full() {
        let now = Instant::now();
        let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let mut cache = DnsCache::new(2);
        let first = key("first.example");
        let second = key("second.example");
        let third = key("third.example");

        cache.insert(first.clone(), vec![address], now);
        cache.insert(second.clone(), vec![address], now + Duration::from_secs(1));
        let _ = cache.get(&first, now + Duration::from_secs(2));
        cache.insert(third.clone(), vec![address], now + Duration::from_secs(3));

        assert!(cache.get(&first, now + Duration::from_secs(3)).is_some());
        assert!(cache.get(&second, now + Duration::from_secs(3)).is_none());
        assert!(cache.get(&third, now + Duration::from_secs(3)).is_some());
    }
}
