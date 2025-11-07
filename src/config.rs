use clap::Parser;
use anyhow::{anyhow, Result};
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
            if config.cert.is_none() {
                config.cert = file_config.cert;
            }
            if config.key.is_none() {
                config.key = file_config.key;
            }
        }

        // 验证密码不为空
        if config.password.is_empty() {
            return Err(anyhow!("Password must be provided either via --password or config file"));
        }

        if config.enable_ws && config.enable_grpc {
            return Err(anyhow!("WebSocket mode and gRPC mode cannot be enabled simultaneously"));
        }

        Ok(config)
    }
}

// =============== TOML 配置部分 ==================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub tls: Option<TlsSettings>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    pub cert: String,
    pub key: String,
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
            },
            tls: Some(TlsSettings {
                cert: "/path/to/cert.pem".to_string(),
                key: "/path/to/key.pem".to_string(),
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
            cert: self.tls.as_ref().map(|t| t.cert.clone()),
            key: self.tls.as_ref().map(|t| t.key.clone()),
            config_file: None,
            generate_config: None,
        }
    }
}
