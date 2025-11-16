use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// 内存池：复用缓冲区，减少内存分配
/// 
/// 使用引用计数和队列管理缓冲区，实现零分配的数据传输
pub struct BufferPool {
    buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    buffer_size: usize,
    max_pool_size: usize,
}

impl BufferPool {
    /// 创建新的缓冲区池
    /// 
    /// - `buffer_size`: 每个缓冲区的大小
    /// - `max_pool_size`: 池中最大缓冲区数量
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            buffers: Arc::new(Mutex::new(VecDeque::new())),
            buffer_size,
            max_pool_size,
        }
    }

    /// 从池中获取一个缓冲区
    /// 
    /// 如果池中有可用缓冲区，直接返回；否则创建新的
    pub fn acquire(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.pop_front().unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// 将缓冲区归还到池中
    /// 
    /// 如果池未满，将缓冲区放回池中复用；否则丢弃
    pub fn release(&self, mut buf: Vec<u8>) {
        // 清空缓冲区内容，但保留容量
        buf.clear();
        
        // 如果缓冲区大小不匹配，丢弃
        if buf.capacity() != self.buffer_size {
            return;
        }

        let mut buffers = self.buffers.lock().unwrap();
        if buffers.len() < self.max_pool_size {
            buffers.push_back(buf);
        }
        // 如果池已满，直接丢弃（让 Rust 自动回收内存）
    }
}

/// 全局缓冲区池（用于 TCP 转发）
use std::sync::OnceLock;

pub static GLOBAL_BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

pub fn get_global_pool() -> &'static BufferPool {
    GLOBAL_BUFFER_POOL.get_or_init(|| BufferPool::new(8192, 32))
}

