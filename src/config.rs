use anyhow::{anyhow, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

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

    /// Enable UDP support
    #[arg(long, default_value_t = true)]
    pub enable_udp: bool,

    /// TLS certificate file path (optional)
    #[arg(long)]
    pub cert: Option<String>,

    /// TLS private key file path (optional)
    #[arg(long)]
    pub key: Option<String>,

    /// Load configuration from TOML file
    #[arg(short = 'c', long)]
    pub config_file: Option<String>,

    /// Generate example configuration file
    #[arg(long)]
    pub generate_config: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,
}

impl ServerConfig {
    /// 从 TOML 文件或命令行参数加载配置
    pub fn load() -> Result<Self> {
        let mut config = Self::parse();

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
            if config.enable_udp {
                config.enable_udp = file_config.enable_udp;
            }
            if config.cert.is_none() {
                config.cert = file_config.cert;
            }
            if config.key.is_none() {
                config.key = file_config.key;
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

        Ok(config)
    }
}

// =============== TOML 配置部分 ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub tls: Option<TlsSettings>,
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

    #[serde(default = "default_enable_udp")]
    pub enable_udp: bool,
}

const fn default_enable_udp() -> bool {
    true
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
                enable_udp: true,
            },
            tls: Some(TlsSettings {
                cert: "/path/to/cert.pem".to_string(),
                key: "/path/to/key.pem".to_string(),
            }),
            log: Some(LogSettings {
                level: "info".to_string(),
            }),
        };

        let toml_str = toml::to_string_pretty(&example)?;
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
            enable_udp: self.server.enable_udp,
            cert: self.tls.as_ref().map(|t| t.cert.clone()),
            key: self.tls.as_ref().map(|t| t.key.clone()),
            config_file: None,
            generate_config: None,
            log_level: self.log.map(|l| l.level),
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
    use super::{normalize_grpc_service_name, normalize_optional_value, normalize_ws_path};

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
}
