use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};
use toml;

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    /// 从字符串解析日志级别
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

pub fn get_log_level_from_args() -> Option<LogLevel> {
    let args: Vec<String> = std::env::args().collect();
    
    let log_level_from_cli = args.iter()
        .position(|a| a == "--log-level")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| LogLevel::from_str(s));
    
    if log_level_from_cli.is_some() {
        return log_level_from_cli;
    }
    
    args.iter()
        .position(|a| a == "--config-file" || a == "-c")
        .and_then(|i| args.get(i + 1))
        .and_then(|config_path| {
            std::fs::read_to_string(config_path).ok()
                .and_then(|content| {
                    toml::from_str::<toml::Value>(&content).ok()
                        .and_then(|v| v.get("log")?.get("level")?.as_str().map(|s| s.to_string()))
                        .and_then(|s| LogLevel::from_str(&s))
                })
        })
}

pub fn init_logger(log_level: Option<LogLevel>) {
    let filter = if let Ok(env_filter) = EnvFilter::try_from_default_env() {
        env_filter
    } else {
        let level = log_level.unwrap_or_default();
        EnvFilter::new(&format!("trojan_rs={}", level.as_str()))
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(true)
                .with_ansi(true)
                .compact(),
        )
        .init();
}

pub mod log {
    pub use tracing::{debug, error, info, warn};

    /// 记录连接事件
    pub fn connection(addr: &str, event: &str) {
        info!(peer = addr, event = event, "Connection");
    }

    /// 记录认证事件
    pub fn authentication(addr: &str, success: bool) {
        if success {
            info!(peer = addr, "Authentication successful");
        } else {
            warn!(peer = addr, "Authentication failed");
        }
    }

    /// 记录传输层事件
    #[allow(dead_code)]
    pub fn transport(transport: &str, event: &str, details: Option<&str>) {
        if let Some(details) = details {
            info!(transport = transport, event = event, details = details, "Transport");
        } else {
            info!(transport = transport, event = event, "Transport");
        }
    }

    /// 记录协议解析事件
    #[allow(dead_code)]
    pub fn protocol(event: &str, error: Option<&str>) {
        if let Some(err) = error {
            warn!(event = event, error = err, "Protocol");
        } else {
            debug!(event = event, "Protocol");
        }
    }
}

