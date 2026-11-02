use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, net::SocketAddr, path::Path};

use crate::grpc::{
    GrpcLimits, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS, DEFAULT_GRPC_MAX_MESSAGE_BYTES,
    DEFAULT_GRPC_MAX_READ_BUFFER_BYTES, DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES, MAX_FRAME_SIZE,
};

pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub const DEFAULT_MAX_TLS_HANDSHAKES: usize = 64;
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
pub const DEFAULT_ACME_CACHE_DIR: &str = "/var/lib/trojan-rs/acme";

/// Shared, built-in ACME configuration. Certificates are provisioned and
/// renewed with TLS-ALPN-01; individual inbounds opt into it with `acme = true`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    pub domain: String,
    pub email: String,
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: String,
    #[serde(default)]
    pub staging: bool,
}
/// Settings for a REALITY listener.  The destination is the public TLS site
/// mirrored for unauthenticated connections (for example `www.example.com:443`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealitySettings {
    pub dest: String,
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub max_time_diff_ms: Option<u64>,
}

/// Transport selected for one independently bound inbound listener.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InboundTransport {
    #[default]
    Tcp,
    #[serde(rename = "websocket", alias = "web_socket")]
    WebSocket,
    Grpc,
}

/// A listener declared in TOML's `[[inbounds]]` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundSettings {
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen: Vec<String>,
    #[serde(default)]
    pub transport: InboundTransport,
    pub password: String,
    #[serde(default)]
    pub unix_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub grpc_service_name: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    #[serde(default)]
    pub acme: bool,
    #[serde(default)]
    pub reality: Option<RealityTomlSettings>,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan Server")]
pub struct ServerConfig {
    #[arg(skip)]
    pub host: String,

    #[arg(skip)]
    pub port: String,

    #[arg(skip)]
    pub password: String,

    #[arg(skip)]
    pub enable_ws: bool,

    #[arg(skip)]
    pub enable_grpc: bool,

    #[arg(skip)]
    pub ws_host: Option<String>,

    #[arg(skip)]
    pub ws_path: Option<String>,

    #[arg(skip)]
    pub grpc_service_name: Option<String>,

    #[arg(skip)]
    pub grpc_max_concurrent_streams: u32,

    #[arg(skip)]
    pub grpc_max_read_buffer_bytes: usize,

    #[arg(skip)]
    pub grpc_max_message_bytes: usize,

    #[arg(skip)]
    pub grpc_max_send_queue_bytes: usize,

    #[arg(skip)]
    pub max_connections: usize,

    #[arg(skip)]
    pub max_tls_handshakes: usize,

    #[arg(skip)]
    pub max_connections_per_ip: usize,

    #[arg(skip)]
    pub cert: Option<String>,

    #[arg(skip)]
    pub key: Option<String>,

    #[arg(skip)]
    pub cert_chain: Vec<String>,

    #[arg(skip)]
    pub acme: Option<AcmeSettings>,

    #[arg(skip)]
    pub use_acme: bool,

    #[arg(skip)]
    pub enable_reality: bool,

    #[arg(skip)]
    pub reality_dest: Option<String>,

    #[arg(skip)]
    pub reality_private_key: Option<String>,

    #[arg(skip)]
    pub reality_short_ids: Vec<String>,

    #[arg(skip)]
    pub reality_max_time_diff_ms: Option<u64>,

    #[arg(skip)]
    pub unix_path: Option<String>,

    /// Load configuration from TOML file
    #[arg(short = 'c', long)]
    pub config_file: Option<String>,

    /// Generate example configuration file
    #[arg(long)]
    pub generate_config: Option<String>,

    /// Generate an X25519 keypair for REALITY and exit
    #[arg(long, default_value_t = false)]
    pub generate_reality_keypair: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,

    /// TOML-only listener definitions. At least one is required at runtime.
    #[arg(skip)]
    pub inbounds: Vec<InboundSettings>,

    /// Resolved socket address for one expanded inbound.
    #[arg(skip)]
    pub listen_addr: Option<String>,

    #[arg(skip)]
    pub inbound_tag: Option<String>,
}

impl ServerConfig {
    /// 从 TOML 文件或命令行参数加载配置
    pub fn load() -> Result<Self> {
        let config = Self::parse();

        if config.generate_reality_keypair {
            let (private_key, public_key) = crate::reality::generate_keypair()?;
            println!("Private key: {private_key}");
            println!("Public key:  {public_key}");
            std::process::exit(0);
        }

        // 如果指定了生成配置文件，生成后退出
        if let Some(ref path) = config.generate_config {
            TomlConfig::generate_example(path)?;
            println!("Example configuration file generated at: {}", path);
            std::process::exit(0);
        }

        let config_path = config.config_file.clone().ok_or_else(|| {
            anyhow!("a TOML configuration file is required; use --config-file <FILE>")
        })?;
        println!("Loading configuration from: {config_path}");
        let mut config = TomlConfig::from_file(&config_path)?.to_server_config();
        config.config_file = Some(config_path);

        if config.inbounds.is_empty()
            || config
                .inbounds
                .iter()
                .any(|inbound| inbound.password.trim().is_empty())
        {
            return Err(anyhow!(
                "every configured inbound must provide a non-empty password"
            ));
        }

        config.acme = config.acme_settings()?;
        config.grpc_limits()?;
        config.validate_connection_limits()?;

        Ok(config)
    }

    /// Expands TOML `[[inbounds]]` into one runtime configuration per socket.
    pub fn expand_inbounds(&self) -> Result<Vec<Self>> {
        if self.inbounds.is_empty() {
            return Err(anyhow!(
                "configuration requires at least one [[inbounds]] entry"
            ));
        }
        if self.enable_reality {
            return Err(anyhow!(
                "move legacy [reality] settings into the appropriate [[inbounds]] entry"
            ));
        }
        let has_acme = self.acme_settings()?.is_some();
        if has_acme && !self.inbounds.iter().any(|inbound| inbound.acme) {
            return Err(anyhow!(
                "[server.acme] is configured but no inbound enables acme"
            ));
        }

        let mut expanded = Vec::new();
        for inbound in &self.inbounds {
            if inbound.listen.is_empty() && inbound.unix_path.is_none() {
                return Err(anyhow!(
                    "each [[inbounds]] entry requires listen and/or unix_path"
                ));
            }
            if [
                inbound.tls.is_some(),
                inbound.acme,
                inbound.reality.is_some(),
            ]
            .into_iter()
            .filter(|enabled| *enabled)
            .count()
                > 1
            {
                return Err(anyhow!(
                    "an inbound can use only one of tls, acme, or reality"
                ));
            }
            if inbound.acme && !has_acme {
                return Err(anyhow!(
                    "an inbound enables ACME but [server.acme] is not configured"
                ));
            }
            if inbound.acme && inbound.unix_path.is_some() {
                return Err(anyhow!(
                    "ACME requires a TCP listener and cannot use unix_path"
                ));
            }

            for listen in &inbound.listen {
                let address: SocketAddr = listen.parse().map_err(|_| {
                    anyhow!(
                        "invalid inbound listen address {listen:?}; use 0.0.0.0:PORT or [::]:PORT"
                    )
                })?;
                let mut config = self.clone();
                config.inbounds.clear();
                config.listen_addr = Some(address.to_string());
                config.inbound_tag = inbound.tag.clone();
                config.enable_ws = matches!(inbound.transport, InboundTransport::WebSocket);
                config.enable_grpc = matches!(inbound.transport, InboundTransport::Grpc);
                config.ws_host = inbound.ws_host.clone();
                config.ws_path = normalize_ws_path(inbound.ws_path.clone())?;
                config.grpc_service_name =
                    normalize_grpc_service_name(inbound.grpc_service_name.clone())?;
                config.password = inbound.password.trim().to_string();
                config.use_acme = inbound.acme;
                if config.password.is_empty() {
                    return Err(anyhow!("inbound password cannot be empty"));
                }

                if let Some(tls) = &inbound.tls {
                    config.cert = Some(tls.cert.clone());
                    config.key = Some(tls.key.clone());
                    config.cert_chain = tls.cert_chain.clone();
                }
                config.enable_reality = inbound.reality.is_some();
                if let Some(reality) = &inbound.reality {
                    config.cert = None;
                    config.key = None;
                    config.reality_dest = Some(reality.dest.clone());
                    config.reality_private_key = Some(reality.private_key.clone());
                    config.reality_short_ids = reality.short_ids.clone();
                    config.reality_max_time_diff_ms = reality.max_time_diff_ms;
                } else {
                    config.reality_dest = None;
                    config.reality_private_key = None;
                    config.reality_short_ids.clear();
                    config.reality_max_time_diff_ms = None;
                }

                config.grpc_limits()?;
                config.reality_settings()?;
                expanded.push(config);
            }

            if let Some(path) = &inbound.unix_path {
                if inbound.reality.is_some() {
                    return Err(anyhow!("REALITY requires a TCP listen address"));
                }

                let mut config = self.clone();
                config.inbounds.clear();
                config.listen_addr = None;
                config.inbound_tag = inbound.tag.clone();
                config.unix_path = normalize_optional_value(
                    Some(path.clone()),
                    "inbound Unix Domain Socket path",
                )?;
                config.enable_ws = matches!(inbound.transport, InboundTransport::WebSocket);
                config.enable_grpc = matches!(inbound.transport, InboundTransport::Grpc);
                config.ws_host = inbound.ws_host.clone();
                config.ws_path = normalize_ws_path(inbound.ws_path.clone())?;
                config.grpc_service_name =
                    normalize_grpc_service_name(inbound.grpc_service_name.clone())?;
                config.password = inbound.password.trim().to_string();
                config.use_acme = inbound.acme;
                if config.password.is_empty() {
                    return Err(anyhow!("inbound password cannot be empty"));
                }
                if let Some(tls) = &inbound.tls {
                    config.cert = Some(tls.cert.clone());
                    config.key = Some(tls.key.clone());
                    config.cert_chain = tls.cert_chain.clone();
                }
                config.enable_reality = false;
                config.reality_dest = None;
                config.reality_private_key = None;
                config.reality_short_ids.clear();
                config.reality_max_time_diff_ms = None;
                config.grpc_limits()?;
                expanded.push(config);
            }
        }
        Ok(expanded)
    }

    pub fn grpc_limits(&self) -> Result<GrpcLimits> {
        if self.grpc_max_concurrent_streams == 0 {
            return Err(anyhow!(
                "gRPC maximum concurrent streams must be greater than zero"
            ));
        }
        if self.grpc_max_message_bytes == 0 {
            return Err(anyhow!(
                "gRPC maximum message size must be greater than zero"
            ));
        }
        if self.grpc_max_read_buffer_bytes < MAX_FRAME_SIZE as usize {
            return Err(anyhow!(
                "gRPC maximum read buffer must be at least {} bytes",
                MAX_FRAME_SIZE
            ));
        }
        if self.grpc_max_read_buffer_bytes < self.grpc_max_message_bytes {
            return Err(anyhow!(
                "gRPC maximum read buffer must not be smaller than the maximum message size"
            ));
        }
        let framed_message_bytes = self
            .grpc_max_message_bytes
            .checked_add(16)
            .ok_or_else(|| anyhow!("gRPC maximum message size is too large"))?;
        if self.grpc_max_send_queue_bytes < framed_message_bytes {
            return Err(anyhow!(
                "gRPC maximum send queue must fit one framed gRPC message"
            ));
        }

        Ok(GrpcLimits {
            max_concurrent_streams: self.grpc_max_concurrent_streams,
            max_read_buffer_bytes: self.grpc_max_read_buffer_bytes,
            max_message_bytes: self.grpc_max_message_bytes,
            max_send_queue_bytes: self.grpc_max_send_queue_bytes,
        })
    }

    pub fn validate_connection_limits(&self) -> Result<()> {
        if self.max_connections == 0 {
            return Err(anyhow!("maximum connections must be greater than zero"));
        }
        if self.max_tls_handshakes == 0 {
            return Err(anyhow!("maximum TLS handshakes must be greater than zero"));
        }
        if self.max_connections_per_ip == 0 {
            return Err(anyhow!(
                "maximum connections per IP must be greater than zero"
            ));
        }
        Ok(())
    }

    pub fn reality_settings(&self) -> Result<Option<RealitySettings>> {
        if !self.enable_reality {
            return Ok(None);
        }

        let dest = self
            .reality_dest
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("REALITY requires --reality-dest"))?;
        let (_, port) = dest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("REALITY destination must be hostname:port"))?;
        let hostname = dest.trim_end_matches(port).trim_end_matches(':');
        if hostname.is_empty()
            || hostname.parse::<std::net::IpAddr>().is_ok()
            || port.parse::<u16>().is_err()
        {
            return Err(anyhow!(
                "REALITY destination must use a DNS hostname and valid port"
            ));
        }

        let private_key = self
            .reality_private_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("REALITY requires --reality-private-key"))?;
        if self.reality_short_ids.is_empty() {
            return Err(anyhow!("REALITY requires at least one --reality-short-id"));
        }

        Ok(Some(RealitySettings {
            dest: dest.to_string(),
            private_key: private_key.to_string(),
            short_ids: self.reality_short_ids.clone(),
            max_time_diff_ms: self.reality_max_time_diff_ms,
        }))
    }

    pub fn acme_settings(&self) -> Result<Option<AcmeSettings>> {
        let Some(mut acme) = self.acme.clone() else {
            return Ok(None);
        };

        acme.domain = normalize_required_value(acme.domain, "ACME domain")?;
        acme.email = normalize_required_value(acme.email, "ACME email")?;
        acme.cache_dir = normalize_required_value(acme.cache_dir, "ACME cache directory")?;
        if !acme.domain.contains('.') || acme.domain.starts_with('.') || acme.domain.ends_with('.')
        {
            return Err(anyhow!("ACME domain must be a fully qualified domain name"));
        }
        if !acme.email.contains('@') {
            return Err(anyhow!("ACME email must contain '@'"));
        }
        Ok(Some(acme))
    }
}

// =============== TOML 配置部分 ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TomlConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub log: Option<LogSettings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<InboundSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    #[serde(default)]
    pub acme: Option<AcmeSettings>,

    #[serde(default = "default_grpc_max_concurrent_streams")]
    pub grpc_max_concurrent_streams: u32,

    #[serde(default = "default_grpc_max_read_buffer_bytes")]
    pub grpc_max_read_buffer_bytes: usize,

    #[serde(default = "default_grpc_max_message_bytes")]
    pub grpc_max_message_bytes: usize,

    #[serde(default = "default_grpc_max_send_queue_bytes")]
    pub grpc_max_send_queue_bytes: usize,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_max_tls_handshakes")]
    pub max_tls_handshakes: usize,

    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityTomlSettings {
    pub dest: String,
    pub private_key: String,
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub max_time_diff_ms: Option<u64>,
}

const fn default_grpc_max_concurrent_streams() -> u32 {
    DEFAULT_GRPC_MAX_CONCURRENT_STREAMS
}

const fn default_grpc_max_read_buffer_bytes() -> usize {
    DEFAULT_GRPC_MAX_READ_BUFFER_BYTES
}

const fn default_grpc_max_message_bytes() -> usize {
    DEFAULT_GRPC_MAX_MESSAGE_BYTES
}

const fn default_grpc_max_send_queue_bytes() -> usize {
    DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES
}

const fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_max_tls_handshakes() -> usize {
    DEFAULT_MAX_TLS_HANDSHAKES
}

const fn default_max_connections_per_ip() -> usize {
    DEFAULT_MAX_CONNECTIONS_PER_IP
}

fn default_acme_cache_dir() -> String {
    DEFAULT_ACME_CACHE_DIR.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    pub cert: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_chain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSettings {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn example_inbounds() -> Vec<InboundSettings> {
    let tls = || {
        Some(TlsSettings {
            cert: "/path/to/cert.pem".to_string(),
            key: "/path/to/key.pem".to_string(),
            cert_chain: Vec::new(),
        })
    };

    vec![
        InboundSettings {
            tag: Some("trojan-tcp".to_string()),
            listen: vec!["0.0.0.0:443".to_string(), "[::]:443".to_string()],
            transport: InboundTransport::Tcp,
            password: "your_password_here".to_string(),
            unix_path: None,
            ws_host: None,
            ws_path: None,
            grpc_service_name: None,
            tls: tls(),
            acme: false,
            reality: None,
        },
        InboundSettings {
            tag: Some("trojan-websocket".to_string()),
            listen: vec!["0.0.0.0:8443".to_string(), "[::]:8443".to_string()],
            transport: InboundTransport::WebSocket,
            password: "your_password_here".to_string(),
            unix_path: None,
            ws_host: Some("cdn.example.com".to_string()),
            ws_path: Some("/trojan".to_string()),
            grpc_service_name: None,
            tls: tls(),
            acme: false,
            reality: None,
        },
        InboundSettings {
            tag: Some("trojan-grpc".to_string()),
            listen: vec!["0.0.0.0:9443".to_string(), "[::]:9443".to_string()],
            transport: InboundTransport::Grpc,
            password: "your_password_here".to_string(),
            unix_path: None,
            ws_host: None,
            ws_path: None,
            grpc_service_name: Some("GunService".to_string()),
            tls: tls(),
            acme: false,
            reality: None,
        },
        InboundSettings {
            tag: Some("trojan-uds".to_string()),
            listen: Vec::new(),
            transport: InboundTransport::WebSocket,
            password: "your_password_here".to_string(),
            unix_path: Some("/run/trojan-rs/trojan.sock".to_string()),
            ws_host: None,
            ws_path: Some("/trojan-uds".to_string()),
            grpc_service_name: None,
            tls: None,
            acme: false,
            reality: None,
        },
    ]
}

impl TomlConfig {
    /// 从文件加载配置
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: TomlConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// 生成示例配置文件
    pub fn generate_example<P: AsRef<Path>>(path: P) -> Result<()> {
        let example = TomlConfig {
            server: ServerSettings {
                acme: None,
                grpc_max_concurrent_streams: default_grpc_max_concurrent_streams(),
                grpc_max_read_buffer_bytes: default_grpc_max_read_buffer_bytes(),
                grpc_max_message_bytes: default_grpc_max_message_bytes(),
                grpc_max_send_queue_bytes: default_grpc_max_send_queue_bytes(),
                max_connections: default_max_connections(),
                max_tls_handshakes: default_max_tls_handshakes(),
                max_connections_per_ip: default_max_connections_per_ip(),
            },
            log: Some(LogSettings {
                level: "info".to_string(),
            }),
            inbounds: example_inbounds(),
        };

        let toml_str = toml::to_string_pretty(&example)?;
        fs::write(path, toml_str)?;
        Ok(())
    }

    /// 转换为 ServerConfig
    pub fn to_server_config(self) -> ServerConfig {
        ServerConfig {
            host: String::new(),
            port: String::new(),
            password: String::new(),
            enable_ws: false,
            enable_grpc: false,
            ws_host: None,
            ws_path: None,
            grpc_service_name: None,
            grpc_max_concurrent_streams: self.server.grpc_max_concurrent_streams,
            grpc_max_read_buffer_bytes: self.server.grpc_max_read_buffer_bytes,
            grpc_max_message_bytes: self.server.grpc_max_message_bytes,
            grpc_max_send_queue_bytes: self.server.grpc_max_send_queue_bytes,
            max_connections: self.server.max_connections,
            max_tls_handshakes: self.server.max_tls_handshakes,
            max_connections_per_ip: self.server.max_connections_per_ip,
            cert: None,
            key: None,
            cert_chain: Vec::new(),
            acme: self.server.acme,
            use_acme: false,
            enable_reality: false,
            reality_dest: None,
            reality_private_key: None,
            reality_short_ids: Vec::new(),
            reality_max_time_diff_ms: None,
            config_file: None,
            generate_config: None,
            generate_reality_keypair: false,
            log_level: self.log.map(|l| l.level),
            unix_path: None,
            inbounds: self.inbounds,
            listen_addr: None,
            inbound_tag: None,
        }
    }
}

fn normalize_optional_value(value: Option<String>, field_name: &str) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(anyhow!("{field_name} cannot be empty"));
            }
            Ok(Some(trimmed.to_string()))
        }
        None => Ok(None),
    }
}

fn normalize_required_value(value: String, field_name: &str) -> Result<String> {
    normalize_optional_value(Some(value), field_name)?
        .ok_or_else(|| anyhow!("{field_name} is required"))
}

fn normalize_ws_path(value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(anyhow!("WebSocket path cannot be empty"));
            }

            let normalized = if trimmed.starts_with('/') {
                trimmed.to_string()
            } else {
                format!("/{trimmed}")
            };

            if normalized.contains('?') || normalized.contains('#') {
                return Err(anyhow!(
                    "WebSocket path must not include a query string or fragment"
                ));
            }

            Ok(Some(normalized))
        }
        None => Ok(None),
    }
}

fn normalize_grpc_service_name(value: Option<String>) -> Result<Option<String>> {
    match normalize_optional_value(value, "gRPC service name")? {
        Some(service_name) => {
            if service_name.contains('/') {
                return Err(anyhow!("gRPC service name must not contain '/'"));
            }
            Ok(Some(service_name))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_grpc_service_name, normalize_optional_value, normalize_ws_path, ServerConfig,
    };
    use clap::Parser;

    fn test_config() -> ServerConfig {
        toml::from_str::<super::TomlConfig>(
            r#"
                [server]

                [[inbounds]]
                listen = ["127.0.0.1:0"]
                password = "test-password"
            "#,
        )
        .unwrap()
        .to_server_config()
    }

    #[test]
    fn each_inbound_requires_its_own_password() {
        let missing_password = toml::from_str::<super::TomlConfig>(
            r#"
                [server]

                [[inbounds]]
                listen = ["127.0.0.1:0"]
            "#,
        );
        assert!(missing_password.is_err());

        let global_setting = toml::from_str::<super::TomlConfig>(
            r#"
                [server]
                enable_udp = true

                [[inbounds]]
                listen = ["127.0.0.1:0"]
                password = "inbound-password"
            "#,
        );
        assert!(global_setting.is_err());
    }

    #[test]
    fn websocket_path_is_normalized_with_leading_slash() {
        assert_eq!(
            normalize_ws_path(Some("ws".to_string())).unwrap(),
            Some("/ws".to_string())
        );
    }

    #[test]
    fn websocket_path_rejects_query_string() {
        assert!(normalize_ws_path(Some("/ws?ed=1".to_string())).is_err());
    }

    #[test]
    fn grpc_service_name_rejects_path_separator() {
        assert!(normalize_grpc_service_name(Some("Gun/Service".to_string())).is_err());
    }

    #[test]
    fn optional_value_rejects_empty_input() {
        assert!(normalize_optional_value(Some("   ".to_string()), "test field").is_err());
    }

    #[test]
    fn acme_is_shared_in_server_settings_and_selected_per_inbound() {
        let config: super::TomlConfig = toml::from_str(
            r#"
                [server]
                acme = { domain = "tunnel.example.com", email = "admin@example.com", staging = true }

                [[inbounds]]
                listen = ["0.0.0.0:443"]
                password = "acme-password"
                acme = true

                [[inbounds]]
                listen = ["127.0.0.1:8443"]
                password = "plain-password"
            "#,
        )
        .unwrap();

        let expanded = config.to_server_config().expand_inbounds().unwrap();
        assert!(expanded[0].use_acme);
        assert!(!expanded[1].use_acme);
        assert_eq!(
            expanded[0].acme.as_ref().unwrap().cache_dir,
            super::DEFAULT_ACME_CACHE_DIR
        );
    }

    #[test]
    fn acme_requires_shared_settings_and_is_mutually_exclusive() {
        let missing_settings: super::TomlConfig = toml::from_str(
            r#"
                [server]
                [[inbounds]]
                listen = ["127.0.0.1:443"]
                password = "test-password"
                acme = true
            "#,
        )
        .unwrap();
        assert!(missing_settings
            .to_server_config()
            .expand_inbounds()
            .is_err());

        let conflicting_settings: super::TomlConfig = toml::from_str(
            r#"
                [server]
                acme = { domain = "tunnel.example.com", email = "admin@example.com" }
                [[inbounds]]
                listen = ["127.0.0.1:443"]
                password = "test-password"
                acme = true
                tls = { cert = "cert.pem", key = "key.pem" }
            "#,
        )
        .unwrap();
        assert!(conflicting_settings
            .to_server_config()
            .expand_inbounds()
            .is_err());
    }

    #[test]
    fn grpc_limits_use_conservative_defaults() {
        let config = test_config();
        let limits = config.grpc_limits().unwrap();

        assert_eq!(limits.max_concurrent_streams, 128);
        assert_eq!(limits.max_read_buffer_bytes, 256 * 1024);
        assert_eq!(limits.max_message_bytes, 16 * 1024);
        assert_eq!(limits.max_send_queue_bytes, 128 * 1024);
    }

    #[test]
    fn grpc_limits_reject_an_undersized_read_buffer() {
        let mut config = test_config();
        config.grpc_max_read_buffer_bytes = 1024;

        assert!(config.grpc_limits().is_err());
    }

    #[test]
    fn connection_limits_use_defaults_and_reject_zero() {
        let default_config = test_config();
        assert_eq!(default_config.max_connections, 1024);
        assert_eq!(default_config.max_tls_handshakes, 64);
        assert_eq!(default_config.max_connections_per_ip, 32);
        assert!(default_config.validate_connection_limits().is_ok());

        let mut invalid_config = test_config();
        invalid_config.max_connections_per_ip = 0;
        assert!(invalid_config.validate_connection_limits().is_err());
    }

    #[test]
    fn reality_requires_complete_dns_based_settings() {
        let mut incomplete = test_config();
        incomplete.enable_reality = true;
        assert!(incomplete.reality_settings().is_err());

        let mut complete = test_config();
        complete.enable_reality = true;
        complete.reality_dest = Some("cover.example:443".to_string());
        complete.reality_private_key =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        complete.reality_short_ids = vec!["0123456789abcdef".to_string()];
        let settings = complete.reality_settings().unwrap().unwrap();
        assert_eq!(settings.dest, "cover.example:443");
        assert_eq!(settings.short_ids, ["0123456789abcdef"]);

        let mut ip_dest = test_config();
        ip_dest.enable_reality = true;
        ip_dest.reality_dest = Some("127.0.0.1:443".to_string());
        ip_dest.reality_private_key =
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        ip_dest.reality_short_ids = vec!["01".to_string()];
        assert!(ip_dest.reality_settings().is_err());
    }

    #[test]
    fn reality_keypair_generation_flag_is_parsed() {
        let config =
            ServerConfig::try_parse_from(["trojan-rs", "--generate-reality-keypair"]).unwrap();
        assert!(config.generate_reality_keypair);
    }

    #[test]
    fn inbounds_expand_addresses_transports_and_per_inbound_settings() {
        let toml_config: super::TomlConfig = toml::from_str(
            r#"
                [server]

                [[inbounds]]
                tag = "tcp-dual-stack"
                listen = ["0.0.0.0:8443", "[::]:8443"]
                transport = "tcp"
                password = "tcp-password"

                [[inbounds]]
                tag = "grpc"
                listen = ["127.0.0.1:9443"]
                transport = "grpc"
                password = "grpc-password"
                tls = { cert = "grpc.crt", key = "grpc.key" }

                [[inbounds]]
                tag = "unix"
                unix_path = "/tmp/trojan-rs.sock"
                transport = "websocket"
                password = "unix-password"
                ws_path = "/trojan-uds"
            "#,
        )
        .unwrap();

        let expanded = toml_config.to_server_config().expand_inbounds().unwrap();
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].listen_addr.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(expanded[1].listen_addr.as_deref(), Some("[::]:8443"));
        assert_eq!(expanded[0].inbound_tag.as_deref(), Some("tcp-dual-stack"));
        assert!(expanded[2].enable_grpc);
        assert_eq!(expanded[2].password, "grpc-password");
        assert_eq!(expanded[2].cert.as_deref(), Some("grpc.crt"));
        assert_eq!(
            expanded[3].unix_path.as_deref(),
            Some("/tmp/trojan-rs.sock")
        );
        assert!(expanded[3].enable_ws);
        assert_eq!(expanded[3].ws_path.as_deref(), Some("/trojan-uds"));
    }

    #[test]
    fn inbound_websocket_transport_uses_the_documented_name() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            transport: super::InboundTransport,
        }
        let wrapper: Wrapper = toml::from_str("transport = \"websocket\"").unwrap();
        assert_eq!(wrapper.transport, super::InboundTransport::WebSocket);
    }

    #[test]
    fn legacy_single_inbound_toml_sections_are_rejected() {
        let old_config = r#"
            [server]

            [tls]
            cert = "cert.pem"
            key = "key.pem"
        "#;
        assert!(toml::from_str::<super::TomlConfig>(old_config).is_err());
    }

    #[test]
    fn runtime_requires_at_least_one_inbound() {
        let mut config = test_config();
        config.inbounds.clear();
        assert!(config.expand_inbounds().is_err());
    }
}
