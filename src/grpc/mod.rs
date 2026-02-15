mod connection;
mod transport;
mod heartbeat;
mod codec;

pub use connection::GrpcH2cConnection;

// HTTP/2 配置
pub(crate) const READ_BUFFER_SIZE: usize = 512 * 1024;
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 1024;
pub(crate) const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;
pub(crate) const INITIAL_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
pub(crate) const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;

// 心跳配置
pub(crate) const PING_INTERVAL_SECS: u64 = 30;
pub(crate) const PING_TIMEOUT_SECS: u64 = 20;
pub(crate) const MAX_MISSED_PINGS: u32 = 3;

// gRPC 配置
pub(crate) const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024;

