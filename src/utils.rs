use hex;
use sha2::{Digest, Sha224};
use std::io::ErrorKind;

// 使用 SHA224 计算密码散列
pub fn hash_password(password: &str) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 28];
    hash.copy_from_slice(&result);
    hash
}

// 将散列后的密码转换为十六进制表示
pub fn password_to_hex(password: &str) -> [u8; 56] {
    let hash = hash_password(password);
    let hex_string = hex::encode(hash);
    let mut hex_bytes: [u8; 56] = [0u8; 56];
    hex_bytes.copy_from_slice(hex_string.as_bytes());
    hex_bytes
}

// 将常见的 IO 错误转为更易理解的中文描述
pub fn describe_io_error(error: &std::io::Error) -> String {
    match error.kind() {
        ErrorKind::TimedOut => "操作超时，目标主机可能未响应".to_string(),
        ErrorKind::ConnectionRefused => "连接被目标主机拒绝".to_string(),
        ErrorKind::ConnectionReset => "连接被远端重置".to_string(),
        ErrorKind::ConnectionAborted => "连接被远端中止".to_string(),
        ErrorKind::NotConnected => "连接尚未建立或已断开".to_string(),
        ErrorKind::AddrInUse => "本地地址已被占用".to_string(),
        ErrorKind::AddrNotAvailable => "本地地址不可用".to_string(),
        ErrorKind::BrokenPipe => "管道已断开，远端可能已关闭连接".to_string(),
        ErrorKind::PermissionDenied => "权限不足，无法完成操作".to_string(),
        ErrorKind::HostUnreachable => "目标主机不可达".to_string(),
        ErrorKind::NetworkUnreachable => "网络不可达".to_string(),
        ErrorKind::Interrupted => "操作被中断，请重试".to_string(),
        ErrorKind::WouldBlock => "资源暂时不可用，请稍后再试".to_string(),
        _ => error.to_string(),
    }
}
