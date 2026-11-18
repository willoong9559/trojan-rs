mod codec;
mod connection;
mod transport;

pub use connection::GrpcH2cConnection;

pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;
pub(crate) const GRPC_FLOW_CONTROL_TIMEOUT_SECS: u64 = 30;
pub(crate) const DEFAULT_GRPC_MAX_CONCURRENT_STREAMS: u32 = 128;
// The read buffer only holds unconsumed HTTP/2 DATA, not complete gRPC
// messages. One advertised maximum HTTP/2 frame is sufficient by default.
pub(crate) const DEFAULT_GRPC_MAX_READ_BUFFER_BYTES: usize = MAX_FRAME_SIZE as usize;
// Match the default receive ceiling used by the standard gRPC implementations.
pub(crate) const DEFAULT_GRPC_MAX_INBOUND_HUNK_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES: usize = 128 * 1024;

/// Per-connection and per-stream resource ceilings for gRPC transport.
#[derive(Debug, Clone, Copy)]
pub struct GrpcLimits {
    pub max_concurrent_streams: u32,
    pub max_read_buffer_bytes: usize,
    /// Largest accepted inbound gRPC Hunk payload.
    pub max_inbound_hunk_bytes: usize,
    pub max_send_queue_bytes: usize,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            // Keep the unconsumed per-stream receive buffer bounded while
            // allowing standard-library-sized inbound gRPC messages.
            max_concurrent_streams: DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            max_read_buffer_bytes: DEFAULT_GRPC_MAX_READ_BUFFER_BYTES,
            max_inbound_hunk_bytes: DEFAULT_GRPC_MAX_INBOUND_HUNK_BYTES,
            max_send_queue_bytes: DEFAULT_GRPC_MAX_SEND_QUEUE_BYTES,
        }
    }
}
