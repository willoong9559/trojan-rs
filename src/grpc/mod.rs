mod connection;
mod transport;
mod codec;

pub use connection::GrpcH2cConnection;

// HTTP/2 配置
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 1024;
pub(crate) const MAX_HEADER_LIST_SIZE: u32 = 60 * 1024;
pub(crate) const MAX_HEADERS_COUNT: usize = 100;
pub(crate) const MAX_HEADER_FIELD_SIZE: usize = 64 * 1024;
pub(crate) const INITIAL_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
pub(crate) const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 24 * 1024 * 1024;
pub(crate) const STREAM_BUFFER_HIGH_WATERMARK: usize = INITIAL_WINDOW_SIZE as usize;
pub(crate) const STREAM_BUFFER_LOW_WATERMARK: usize = STREAM_BUFFER_HIGH_WATERMARK / 2;

// gRPC 配置
pub(crate) const GRPC_MAX_MESSAGE_SIZE: usize = 8 * 1024;
