use hex;
use sha2::{Digest, Sha224};

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
