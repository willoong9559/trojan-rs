mod codec;
mod connection;
mod transport;

pub use connection::GrpcH2cConnection;

// HTTP/2 配置
pub(crate) const READ_BUFFER_SIZE: usize = 512 * 1024;
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 1024;
pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;

// gRPC 配置
// Keep messages below the 64 KiB HTTP/2 frame limit while amortizing gRPC
// framing, allocation, and flow-control work across larger relay reads.
pub(crate) const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024;
pub(crate) const MAX_SEND_QUEUE_BYTES: usize = 512 * 1024;

// Long-lived streams need explicit liveness detection. These values keep the
// connection alive through ordinary NATs while detecting a half-open path in a
// bounded amount of time.
pub(crate) const GRPC_KEEPALIVE_INTERVAL_SECS: u64 = 30;
pub(crate) const GRPC_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
pub(crate) const GRPC_FLOW_CONTROL_TIMEOUT_SECS: u64 = 30;
