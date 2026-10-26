use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::grpc::{
    GrpcLimits, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS, DEFAULT_GRPC_MAX_MESSAGE_BYTES,
    DEFAULT_GRPC_MAX_READ_BUFFER_BYTES, DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES, MAX_FRAME_SIZE,
};

pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;
pub const DEFAULT_MAX_TLS_HANDSHAKES: usize = 64;
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
pub const DEFAULT_ACME_CACHE_DIR: &str = "/var/lib/trojan-rs/acme";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeSettings {
    pub domain: String,
    pub email: String,
    pub cache_dir: String,
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

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan Server")]
pub struct ServerConfig {
    /// Host address
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port number
    #[arg(long, default_value = "35537")]
    pub port: String,

    /// Password
    #[arg(long, default_value = "")]
    pub password: String,

    /// Enable WebSocket mode
    #[arg(long, default_value_t = false)]
    pub enable_ws: bool,

    /// Enable gRPC mode
    #[arg(long, default_value_t = false)]
    pub enable_grpc: bool,

    /// Expected WebSocket Host header
    #[arg(long)]
    pub ws_host: Option<String>,

    /// Expected WebSocket request path
    #[arg(long)]
    pub ws_path: Option<String>,

    /// Expected gRPC service name
    #[arg(long)]
    pub grpc_service_name: Option<String>,

    /// Maximum concurrent gRPC streams per HTTP/2 connection
    #[arg(long, default_value_t = DEFAULT_GRPC_MAX_CONCURRENT_STREAMS)]
    pub grpc_max_concurrent_streams: u32,

    /// Maximum buffered gRPC request bytes per stream
    #[arg(long, default_value_t = DEFAULT_GRPC_MAX_READ_BUFFER_BYTES)]
    pub grpc_max_read_buffer_bytes: usize,

    /// Maximum uncompressed payload in one gRPC message
    #[arg(long, default_value_t = DEFAULT_GRPC_MAX_MESSAGE_BYTES)]
    pub grpc_max_message_bytes: usize,

    /// Maximum queued gRPC response bytes per stream
    #[arg(long, default_value_t = DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES)]
    pub grpc_max_send_queue_bytes: usize,

    /// Maximum active connections, including connections in TLS handshake
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS)]
    pub max_connections: usize,

    /// Maximum concurrent TLS handshakes
    #[arg(long, default_value_t = DEFAULT_MAX_TLS_HANDSHAKES)]
    pub max_tls_handshakes: usize,

    /// Maximum active TCP connections from a single IP address
    #[arg(long, default_value_t = DEFAULT_MAX_CONNECTIONS_PER_IP)]
    pub max_connections_per_ip: usize,

    /// Domain name to provision through Let's Encrypt using TLS-ALPN-01
    #[arg(long)]
    pub acme_domain: Option<String>,

    /// Let's Encrypt account contact email
    #[arg(long)]
    pub acme_email: Option<String>,

    /// Directory for the ACME account and certificate cache
    #[arg(long, default_value = DEFAULT_ACME_CACHE_DIR)]
    pub acme_cache_dir: String,

    /// Use the Let's Encrypt staging environment
    #[arg(long, default_value_t = false)]
    pub acme_staging: bool,

    /// Enable UDP support
    #[arg(long, default_value_t = true)]
    pub enable_udp: bool,

    /// TLS certificate file path (optional)
    #[arg(long)]
    pub cert: Option<String>,

    /// TLS private key file path (optional)
    #[arg(long)]
    pub key: Option<String>,

    /// Enable REALITY instead of ordinary TLS. Requires --reality-dest,
    /// --reality-private-key and at least one --reality-short-id.
    #[arg(long, default_value_t = false)]
    pub enable_reality: bool,

    /// REALITY cover destination in `hostname:port` form
    #[arg(long)]
    pub reality_dest: Option<String>,

    /// REALITY X25519 private key, base64url without padding
    #[arg(long)]
    pub reality_private_key: Option<String>,

    /// Accepted REALITY short ID, 0-16 hexadecimal characters. May be repeated.
    #[arg(long = "reality-short-id")]
    pub reality_short_ids: Vec<String>,

    /// Optional maximum client clock skew for REALITY, in milliseconds
    #[arg(long)]
    pub reality_max_time_diff_ms: Option<u64>,

    /// Unix Domain Socket path (optional)
    #[arg(long)]
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
}

impl ServerConfig {
    /// 从 TOML 文件或命令行参数加载配置
    pub fn load() -> Result<Self> {
        let mut config = Self::parse();

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

        // 如果指定了配置文件，从文件加载
        if let Some(ref config_path) = config.config_file {
            println!("Loading configuration from: {}", config_path);
            let toml_config = TomlConfig::from_file(config_path)?;

            // 转换成 ServerConfig
            let file_config = toml_config.to_server_config();

            // 只有命令行参数为默认值时才使用文件配置
            if config.host == "127.0.0.1" {
                config.host = file_config.host;
            }
            if config.port == "35537" {
                config.port = file_config.port;
            }
            if config.password.is_empty() {
                config.password = file_config.password;
            }
            if !config.enable_ws {
                config.enable_ws = file_config.enable_ws;
            }
            if !config.enable_grpc {
                config.enable_grpc = file_config.enable_grpc;
            }
            if config.ws_host.is_none() {
                config.ws_host = file_config.ws_host;
            }
            if config.ws_path.is_none() {
                config.ws_path = file_config.ws_path;
            }
            if config.grpc_service_name.is_none() {
                config.grpc_service_name = file_config.grpc_service_name;
            }
            if config.grpc_max_concurrent_streams == DEFAULT_GRPC_MAX_CONCURRENT_STREAMS {
                config.grpc_max_concurrent_streams = file_config.grpc_max_concurrent_streams;
            }
            if config.grpc_max_read_buffer_bytes == DEFAULT_GRPC_MAX_READ_BUFFER_BYTES {
                config.grpc_max_read_buffer_bytes = file_config.grpc_max_read_buffer_bytes;
            }
            if config.grpc_max_message_bytes == DEFAULT_GRPC_MAX_MESSAGE_BYTES {
                config.grpc_max_message_bytes = file_config.grpc_max_message_bytes;
            }
            if config.grpc_max_send_queue_bytes == DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES {
                config.grpc_max_send_queue_bytes = file_config.grpc_max_send_queue_bytes;
            }
            if config.max_connections == DEFAULT_MAX_CONNECTIONS {
                config.max_connections = file_config.max_connections;
            }
            if config.max_tls_handshakes == DEFAULT_MAX_TLS_HANDSHAKES {
                config.max_tls_handshakes = file_config.max_tls_handshakes;
            }
            if config.max_connections_per_ip == DEFAULT_MAX_CONNECTIONS_PER_IP {
                config.max_connections_per_ip = file_config.max_connections_per_ip;
            }
            if config.acme_domain.is_none() {
                config.acme_domain = file_config.acme_domain;
            }
            if config.acme_email.is_none() {
                config.acme_email = file_config.acme_email;
            }
            if config.acme_cache_dir == DEFAULT_ACME_CACHE_DIR {
                config.acme_cache_dir = file_config.acme_cache_dir;
            }
            if !config.acme_staging {
                config.acme_staging = file_config.acme_staging;
            }
            if config.enable_udp {
                config.enable_udp = file_config.enable_udp;
            }
            if config.cert.is_none() {
                config.cert = file_config.cert;
            }
            if config.key.is_none() {
                config.key = file_config.key;
            }
            if !config.enable_reality {
                config.enable_reality = file_config.enable_reality;
            }
            if config.reality_dest.is_none() {
                config.reality_dest = file_config.reality_dest;
            }
            if config.reality_private_key.is_none() {
                config.reality_private_key = file_config.reality_private_key;
            }
            if config.reality_short_ids.is_empty() {
                config.reality_short_ids = file_config.reality_short_ids;
            }
            if config.reality_max_time_diff_ms.is_none() {
                config.reality_max_time_diff_ms = file_config.reality_max_time_diff_ms;
            }
            if config.unix_path.is_none() {
                config.unix_path = file_config.unix_path;
            }
            if config.log_level.is_none() {
                config.log_level = file_config.log_level;
            }
        }

        // 验证密码不为空
        if config.password.is_empty() {
            return Err(anyhow!(
                "Password must be provided either via --password or config file"
            ));
        }

        if config.enable_ws && config.enable_grpc {
            return Err(anyhow!(
                "WebSocket mode and gRPC mode cannot be enabled simultaneously"
            ));
        }

        config.ws_host = normalize_optional_value(config.ws_host, "WebSocket host")?;
        config.ws_path = normalize_ws_path(config.ws_path)?;
        config.grpc_service_name = normalize_grpc_service_name(config.grpc_service_name)?;
        config.unix_path = normalize_optional_value(config.unix_path, "Unix Domain Socket path")?;
        config.grpc_limits()?;
        config.validate_connection_limits()?;
        config.acme_settings()?;
        config.reality_settings()?;

        if config.enable_reality && (config.cert.is_some() || config.key.is_some()) {
            return Err(anyhow!(
                "REALITY cannot be enabled together with a static TLS certificate"
            ));
        }
        if config.enable_reality && config.acme_domain.is_some() {
            return Err(anyhow!("REALITY cannot be enabled together with ACME"));
        }

        Ok(config)
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

    pub fn acme_settings(&self) -> Result<Option<AcmeSettings>> {
        let domain = normalize_optional_value(self.acme_domain.clone(), "ACME domain")?;
        let email = normalize_optional_value(self.acme_email.clone(), "ACME email")?;

        match (domain, email) {
            (None, None) => Ok(None),
            (Some(domain), Some(email)) => {
                if self.cert.is_some() || self.key.is_some() {
                    return Err(anyhow!(
                        "ACME settings cannot be combined with --cert or --key"
                    ));
                }
                if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
                    return Err(anyhow!("ACME domain must be a fully qualified domain name"));
                }
                if !email.contains('@') {
                    return Err(anyhow!("ACME email must contain '@'"));
                }
                let cache_dir = self.acme_cache_dir.trim();
                if cache_dir.is_empty() {
                    return Err(anyhow!("ACME cache directory cannot be empty"));
                }
                Ok(Some(AcmeSettings {
                    domain,
                    email,
                    cache_dir: cache_dir.to_string(),
                    staging: self.acme_staging,
                }))
            }
            _ => Err(anyhow!(
                "ACME domain and ACME email must be configured together"
            )),
        }
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
}

// =============== TOML 配置部分 ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub tls: Option<TlsSettings>,
    #[serde(default)]
    pub reality: Option<RealityTomlSettings>,
    #[serde(default)]
    pub log: Option<LogSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: String,
    pub password: String,

    #[serde(default)]
    pub enable_ws: bool,

    #[serde(default)]
    pub enable_grpc: bool,

    #[serde(default)]
    pub ws_host: Option<String>,

    #[serde(default)]
    pub ws_path: Option<String>,

    #[serde(default)]
    pub grpc_service_name: Option<String>,

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

    #[serde(default = "default_enable_udp")]
    pub enable_udp: bool,

    #[serde(default)]
    pub unix_path: Option<String>,

    #[serde(default)]
    pub acme_domain: Option<String>,

    #[serde(default)]
    pub acme_email: Option<String>,

    #[serde(default = "default_acme_cache_dir")]
    pub acme_cache_dir: String,

    #[serde(default)]
    pub acme_staging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityTomlSettings {
    pub dest: String,
    pub private_key: String,
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub max_time_diff_ms: Option<u64>,
}

const fn default_enable_udp() -> bool {
    true
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
pub struct TlsSettings {
    pub cert: String,
    pub key: String,
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
                host: "127.0.0.1".to_string(),
                port: "35537".to_string(),
                password: "your_password_here".to_string(),
                enable_ws: true,
                enable_grpc: false,
                ws_host: Some("cdn.example.com".to_string()),
                ws_path: Some("/ws".to_string()),
                grpc_service_name: Some("GunService".to_string()),
                grpc_max_concurrent_streams: default_grpc_max_concurrent_streams(),
                grpc_max_read_buffer_bytes: default_grpc_max_read_buffer_bytes(),
                grpc_max_message_bytes: default_grpc_max_message_bytes(),
                grpc_max_send_queue_bytes: default_grpc_max_send_queue_bytes(),
                max_connections: default_max_connections(),
                max_tls_handshakes: default_max_tls_handshakes(),
                max_connections_per_ip: default_max_connections_per_ip(),
                enable_udp: true,
                unix_path: None,
                acme_domain: None,
                acme_email: None,
                acme_cache_dir: default_acme_cache_dir(),
                acme_staging: false,
            },
            tls: Some(TlsSettings {
                cert: "/path/to/cert.pem".to_string(),
                key: "/path/to/key.pem".to_string(),
            }),
            reality: None,
            log: Some(LogSettings {
                level: "info".to_string(),
            }),
        };

        let mut toml_str = toml::to_string_pretty(&example)?;
        toml_str.push_str(
            r#"

# REALITY is an alternative to [tls] and ACME. Uncomment this block only after
# removing [tls] and the ACME settings above.
# [reality]
# dest = "www.example.com:443"
# private_key = "base64url-x25519-private-key"
# short_ids = ["0123456789abcdef"]
# max_time_diff_ms = 60000
"#,
        );
        fs::write(path, toml_str)?;
        Ok(())
    }

    /// 转换为 ServerConfig
    pub fn to_server_config(self) -> ServerConfig {
        ServerConfig {
            host: self.server.host,
            port: self.server.port,
            password: self.server.password,
            enable_ws: self.server.enable_ws,
            enable_grpc: self.server.enable_grpc,
            ws_host: self.server.ws_host,
            ws_path: self.server.ws_path,
            grpc_service_name: self.server.grpc_service_name,
            grpc_max_concurrent_streams: self.server.grpc_max_concurrent_streams,
            grpc_max_read_buffer_bytes: self.server.grpc_max_read_buffer_bytes,
            grpc_max_message_bytes: self.server.grpc_max_message_bytes,
            grpc_max_send_queue_bytes: self.server.grpc_max_send_queue_bytes,
            max_connections: self.server.max_connections,
            max_tls_handshakes: self.server.max_tls_handshakes,
            max_connections_per_ip: self.server.max_connections_per_ip,
            enable_udp: self.server.enable_udp,
            cert: self.tls.as_ref().map(|t| t.cert.clone()),
            key: self.tls.as_ref().map(|t| t.key.clone()),
            enable_reality: self.reality.is_some(),
            reality_dest: self.reality.as_ref().map(|r| r.dest.clone()),
            reality_private_key: self.reality.as_ref().map(|r| r.private_key.clone()),
            reality_short_ids: self
                .reality
                .as_ref()
                .map(|r| r.short_ids.clone())
                .unwrap_or_default(),
            reality_max_time_diff_ms: self.reality.as_ref().and_then(|r| r.max_time_diff_ms),
            config_file: None,
            generate_config: None,
            generate_reality_keypair: false,
            log_level: self.log.map(|l| l.level),
            unix_path: self.server.unix_path,
            acme_domain: self.server.acme_domain,
            acme_email: self.server.acme_email,
            acme_cache_dir: self.server.acme_cache_dir,
            acme_staging: self.server.acme_staging,
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
    fn grpc_limits_use_conservative_defaults() {
        let config =
            ServerConfig::try_parse_from(["trojan-rs", "--password", "test-password"]).unwrap();
        let limits = config.grpc_limits().unwrap();

        assert_eq!(limits.max_concurrent_streams, 128);
        assert_eq!(limits.max_read_buffer_bytes, 256 * 1024);
        assert_eq!(limits.max_message_bytes, 16 * 1024);
        assert_eq!(limits.max_send_queue_bytes, 128 * 1024);
    }

    #[test]
    fn grpc_limits_reject_an_undersized_read_buffer() {
        let config = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--grpc-max-read-buffer-bytes",
            "1024",
        ])
        .unwrap();

        assert!(config.grpc_limits().is_err());
    }

    #[test]
    fn connection_limits_use_defaults_and_reject_zero() {
        let default_config =
            ServerConfig::try_parse_from(["trojan-rs", "--password", "test-password"]).unwrap();
        assert_eq!(default_config.max_connections, 1024);
        assert_eq!(default_config.max_tls_handshakes, 64);
        assert_eq!(default_config.max_connections_per_ip, 32);
        assert!(default_config.validate_connection_limits().is_ok());

        let invalid_config = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--max-connections-per-ip",
            "0",
        ])
        .unwrap();
        assert!(invalid_config.validate_connection_limits().is_err());
    }

    #[test]
    fn acme_requires_domain_and_email_without_static_certificates() {
        let config = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--acme-domain",
            "tunnel.example.com",
            "--acme-email",
            "admin@example.com",
            "--acme-staging",
        ])
        .unwrap();
        assert_eq!(
            config.acme_settings().unwrap(),
            Some(super::AcmeSettings {
                domain: "tunnel.example.com".to_string(),
                email: "admin@example.com".to_string(),
                cache_dir: super::DEFAULT_ACME_CACHE_DIR.to_string(),
                staging: true,
            })
        );

        let incomplete = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--acme-domain",
            "tunnel.example.com",
        ])
        .unwrap();
        assert!(incomplete.acme_settings().is_err());
    }

    #[test]
    fn reality_requires_complete_dns_based_settings() {
        let incomplete = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--enable-reality",
        ])
        .unwrap();
        assert!(incomplete.reality_settings().is_err());

        let complete = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--enable-reality",
            "--reality-dest",
            "cover.example:443",
            "--reality-private-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--reality-short-id",
            "0123456789abcdef",
        ])
        .unwrap();
        let settings = complete.reality_settings().unwrap().unwrap();
        assert_eq!(settings.dest, "cover.example:443");
        assert_eq!(settings.short_ids, ["0123456789abcdef"]);

        let ip_dest = ServerConfig::try_parse_from([
            "trojan-rs",
            "--password",
            "test-password",
            "--enable-reality",
            "--reality-dest",
            "127.0.0.1:443",
            "--reality-private-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--reality-short-id",
            "01",
        ])
        .unwrap();
        assert!(ip_dest.reality_settings().is_err());
    }

    #[test]
    fn reality_keypair_generation_flag_is_parsed() {
        let config =
            ServerConfig::try_parse_from(["trojan-rs", "--generate-reality-keypair"]).unwrap();
        assert!(config.generate_reality_keypair);
    }
}
