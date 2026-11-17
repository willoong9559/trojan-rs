use anyhow::{anyhow, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use crate::socks5::Address;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundPolicySettings {
    #[serde(default = "default_block_private_addresses")]
    pub block_private_addresses: bool,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
    #[serde(default)]
    pub deny_domains: Vec<String>,
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    #[serde(default)]
    pub deny_ports: Vec<u16>,
}

fn default_block_private_addresses() -> bool {
    true
}

impl Default for OutboundPolicySettings {
    fn default() -> Self {
        Self {
            block_private_addresses: true,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            allow_ports: Vec::new(),
            deny_ports: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct OutboundPolicy {
    settings: OutboundPolicySettings,
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

impl OutboundPolicySettings {
    pub fn validate(&self) -> Result<()> {
        self.build().map(|_| ())
    }
    pub fn build(&self) -> Result<OutboundPolicy> {
        let parse = |items: &[String], name| -> Result<Vec<IpNet>> {
            items
                .iter()
                .map(|item| {
                    item.parse()
                        .map_err(|_| anyhow!("invalid {name} CIDR {item:?}"))
                })
                .collect()
        };
        for domain in self.allow_domains.iter().chain(&self.deny_domains) {
            if normalize_domain(domain).is_none() {
                return Err(anyhow!("outbound domain rule cannot be empty"));
            }
        }
        Ok(OutboundPolicy {
            settings: self.clone(),
            allow: parse(&self.allow_cidrs, "outbound")?,
            deny: parse(&self.deny_cidrs, "outbound")?,
        })
    }
}

static POLICY: OnceLock<OutboundPolicy> = OnceLock::new();
pub fn initialize(policy: OutboundPolicy) -> Result<()> {
    POLICY
        .set(policy)
        .map_err(|_| anyhow!("outbound policy was already initialized"))
}
#[cfg(not(test))]
fn policy() -> &'static OutboundPolicy {
    POLICY.get_or_init(|| {
        OutboundPolicySettings::default()
            .build()
            .expect("default policy is valid")
    })
}
#[cfg(test)]
fn policy() -> &'static OutboundPolicy {
    POLICY.get_or_init(|| {
        let mut settings = OutboundPolicySettings::default();
        settings.block_private_addresses = false;
        settings.build().expect("test policy is valid")
    })
}

impl OutboundPolicy {
    pub fn check_address(&self, address: &Address) -> Result<()> {
        let port = address.port();
        self.check_port(port)?;
        if let Address::Domain(domain, _) = address {
            self.check_domain(domain)?;
        }
        Ok(())
    }
    pub fn check_socket(&self, address: SocketAddr) -> Result<()> {
        self.check_port(address.port())?;
        let ip = address.ip();
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return Err(anyhow!("outbound address {ip} is denied"));
        }
        if self.allow.iter().any(|net| net.contains(&ip)) {
            return Ok(());
        }
        if !self.allow.is_empty() {
            return Err(anyhow!("outbound address {ip} is not allowed"));
        }
        if self.settings.block_private_addresses && is_private_or_special(ip) {
            return Err(anyhow!(
                "outbound private or special address {ip} is blocked"
            ));
        }
        Ok(())
    }
    fn check_port(&self, port: u16) -> Result<()> {
        if self.settings.deny_ports.contains(&port) {
            return Err(anyhow!("outbound port {port} is denied"));
        }
        if !self.settings.allow_ports.is_empty() && !self.settings.allow_ports.contains(&port) {
            return Err(anyhow!("outbound port {port} is not allowed"));
        }
        Ok(())
    }
    fn check_domain(&self, domain: &str) -> Result<()> {
        let domain =
            normalize_domain(domain).ok_or_else(|| anyhow!("outbound domain cannot be empty"))?;
        if self
            .settings
            .deny_domains
            .iter()
            .filter_map(|d| normalize_domain(d))
            .any(|rule| domain_matches(&domain, &rule))
        {
            return Err(anyhow!("outbound domain {domain} is denied"));
        }
        if !self.settings.allow_domains.is_empty()
            && !self
                .settings
                .allow_domains
                .iter()
                .filter_map(|d| normalize_domain(d))
                .any(|rule| domain_matches(&domain, &rule))
        {
            return Err(anyhow!("outbound domain {domain} is not allowed"));
        }
        Ok(())
    }
}

pub fn check_address(address: &Address) -> Result<()> {
    policy().check_address(address)
}
pub fn check_socket(address: SocketAddr) -> Result<()> {
    policy().check_socket(address)
}
fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}
fn domain_matches(domain: &str, rule: &str) -> bool {
    domain == rule
        || domain
            .strip_suffix(rule)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
fn is_private_or_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
        }
    }
}
