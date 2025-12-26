use std::sync::Arc;
use std::collections::VecDeque;
use tokio::sync::Mutex;

/// 内存池：复用缓冲区，减少内存分配
/// 

pub struct BufferPool {
    buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl BufferPool {
    /// 创建新的缓冲区池
    /// 
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(VecDeque::with_capacity(max_pool_size / 2))),
            buffer_size,
            max_pool_size,
        }
    }

    /// 从池中获取一个缓冲区
    /// 
    /// 如果池中有可用缓冲区，直接返回；否则创建新的
    pub async fn acquire(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().await;
        buffers.pop_front().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// 将缓冲区归还到池中
    /// 
    /// 如果池未满，将缓冲区放回池中复用；否则丢弃
    /// 优化：如果池超过最大大小，清理多余的缓冲区
    pub async fn release(&self, mut buf: Vec<u8>) {
        // 清空缓冲区内容，但保留容量
        buf.clear();
        
        // 如果缓冲区大小不匹配，丢弃
        if buf.capacity() != self.buffer_size {
            return;
        }

        let mut buffers = self.buffers.lock().await;
        if buffers.len() < self.max_pool_size {
            buffers.push_back(buf);
        } else {
            // 池已满，丢弃缓冲区（让 Rust 自动回收内存）
            // 如果池中缓冲区过多，清理一些旧的（保持池大小在合理范围）
            if buffers.len() > self.max_pool_size * 2 {
                // 清理一半的缓冲区，避免内存泄漏
                let to_remove = buffers.len() - self.max_pool_size;
                for _ in 0..to_remove {
                    buffers.pop_front();
                }
            }
        }
    }
}

/// 全局缓冲区池（用于 TCP 转发）
use std::sync::OnceLock;

pub static GLOBAL_BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

pub fn get_global_pool() -> &'static BufferPool {
    GLOBAL_BUFFER_POOL.get_or_init(|| BufferPool::new(4096, 128))
}

