use std::io;
use thiserror::Error;

/// Trojan 服务器统一的错误类型
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum TrojanError {
    /// IO 错误
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// 配置错误
    #[error("Configuration error: {0}")]
    Config(String),

    /// 协议解析错误
    #[error("Protocol parse error: {0}")]
    ProtocolParse(String),

    /// 认证错误
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// TLS 错误
    #[error("TLS error: {0}")]
    Tls(String),

    /// 网络连接错误
    #[error("Network connection error: {0}")]
    Connection(String),

    /// 传输层错误
    #[error("Transport error: {0}")]
    Transport(String),

    /// 其他错误
    #[error("{0}")]
    Other(String),
}

/// 结果类型别名
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, TrojanError>;

impl From<anyhow::Error> for TrojanError {
    fn from(err: anyhow::Error) -> Self {
        TrojanError::Other(err.to_string())
    }
}

impl From<toml::de::Error> for TrojanError {
    fn from(err: toml::de::Error) -> Self {
        TrojanError::Config(format!("TOML parse error: {}", err))
    }
}

