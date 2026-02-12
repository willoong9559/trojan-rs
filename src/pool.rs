use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub const DEFAULT_MAX_IDLE_PER_TARGET: usize = 16;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

struct IdleConnection {
    stream: TcpStream,
    last_used: Instant,
}

pub struct OutboundConnectionPool {
    max_idle_per_target: usize,
    idle_timeout: Duration,
    idle: Mutex<HashMap<SocketAddr, VecDeque<IdleConnection>>>,
}

impl OutboundConnectionPool {
    pub fn new(max_idle_per_target: usize, idle_timeout: Duration) -> Self {
        Self {
            max_idle_per_target,
            idle_timeout,
            idle: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_MAX_IDLE_PER_TARGET,
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        )
    }

    pub fn take_idle_connection(&self, target: SocketAddr) -> Option<TcpStream> {
        let now = Instant::now();
        let mut guard = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired(&mut guard, now, self.idle_timeout);

        let queue = guard.get_mut(&target)?;
        let candidate = queue.pop_back()?;
        if queue.is_empty() {
            guard.remove(&target);
        }

        if now.duration_since(candidate.last_used) > self.idle_timeout {
            return None;
        }
        if let Ok(Some(_)) = candidate.stream.take_error() {
            return None;
        }
        Some(candidate.stream)
    }

    pub fn store_idle_connection(&self, target: SocketAddr, stream: TcpStream) {
        if self.max_idle_per_target == 0 {
            return;
        }
        if let Ok(Some(_)) = stream.take_error() {
            return;
        }

        let now = Instant::now();
        let mut guard = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        Self::cleanup_expired(&mut guard, now, self.idle_timeout);

        let queue = guard.entry(target).or_default();
        while queue.len() >= self.max_idle_per_target {
            queue.pop_front();
        }
        queue.push_back(IdleConnection {
            stream,
            last_used: now,
        });
    }

    fn cleanup_expired(
        map: &mut HashMap<SocketAddr, VecDeque<IdleConnection>>,
        now: Instant,
        timeout: Duration,
    ) {
        map.retain(|_, queue| {
            while let Some(front) = queue.front() {
                if now.duration_since(front.last_used) <= timeout {
                    break;
                }
                queue.pop_front();
            }
            !queue.is_empty()
        });
    }
}

