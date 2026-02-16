mod connection;
mod transport;
mod codec;

pub use connection::GrpcH2cConnection;

// HTTP/2 配置
pub(crate) const READ_BUFFER_SIZE: usize = 512 * 1024;
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 1024;
pub(crate) const MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;
pub(crate) const INITIAL_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
pub(crate) const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;

// gRPC 配置
pub(crate) const GRPC_MAX_MESSAGE_SIZE: usize = 32 * 1024;
pub(crate) const MAX_SEND_QUEUE_BYTES: usize = 512 * 1024;
