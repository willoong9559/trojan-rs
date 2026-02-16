mod connection;
mod transport;
mod heartbeat;
mod codec;

pub use connection::GrpcH2cConnection;

// HTTP/2 配置
pub(crate) const READ_BUFFER_SIZE: usize = 256 * 1024;
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 1024;
pub(crate) const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;
pub(crate) const INITIAL_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
pub(crate) const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

// 心跳配置
pub(crate) const PING_INTERVAL_SECS: u64 = 60;
pub(crate) const PING_TIMEOUT_SECS: u64 = 90;
pub(crate) const MAX_MISSED_PINGS: u32 = 5;

// gRPC 配置
pub(crate) const GRPC_MAX_MESSAGE_SIZE: usize = 64 * 1024;
pub(crate) const STREAM_WRITE_TIMEOUT_SECS: u64 = 60;
