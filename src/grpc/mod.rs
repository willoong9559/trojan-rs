mod codec;
mod connection;
mod transport;

pub use connection::GrpcH2cConnection;

pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;
pub(crate) const GRPC_FLOW_CONTROL_TIMEOUT_SECS: u64 = 30;
pub(crate) const DEFAULT_GRPC_MAX_CONCURRENT_STREAMS: u32 = 128;
pub(crate) const DEFAULT_GRPC_MAX_READ_BUFFER_BYTES: usize = 256 * 1024;
pub(crate) const DEFAULT_GRPC_MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub(crate) const DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES: usize = 128 * 1024;

/// Per-connection and per-stream resource ceilings for gRPC transport.
#[derive(Debug, Clone, Copy)]
pub struct GrpcLimits {
    pub max_concurrent_streams: u32,
    pub max_read_buffer_bytes: usize,
    pub max_message_bytes: usize,
    pub max_send_queue_bytes: usize,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            // 1024 concurrent streams with 1 MiB of receive buffering each is
            // far too easy to exhaust under a single bad connection.
            max_concurrent_streams: DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            max_read_buffer_bytes: DEFAULT_GRPC_MAX_READ_BUFFER_BYTES,
            max_message_bytes: DEFAULT_GRPC_MAX_MESSAGE_BYTES,
            max_send_queue_bytes: DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES,
        }
    }
}
