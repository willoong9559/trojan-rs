//! Native Shadowsocks TCP support for the legacy AEAD `aes-256-gcm` method.
//!
//! The transport is deliberately separate from Trojan's header format. It uses
//! Shadowsocks' salted HKDF session keys and encrypted length-prefixed chunks.

use crate::logger::log;
use crate::socks5;
use crate::{connect_first_available, CONNECTION_TIMEOUT_SECS};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use anyhow::{anyhow, Result};
use getrandom::fill as random_fill;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = KEY_LEN;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_PAYLOAD_LEN: usize = 0x3fff;
const IDLE_CHECK_SECS: u64 = 30;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

/// A Shadowsocks server using the interoperable legacy AEAD `aes-256-gcm`
/// method. The configured password is expanded once into a master key.
#[derive(Clone)]
pub struct Server {
    master_key: [u8; KEY_LEN],
}

impl Server {
    pub fn new(password: &str) -> Self {
        Self {
            master_key: evp_bytes_to_key(password),
        }
    }

    pub async fn handle_connection<S>(&self, stream: S, peer_addr: String) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let mut client_reader = Reader::new(read_half, self.master_key);
        let client_writer = Writer::new(write_half, self.master_key);

        let first_payload = client_reader
            .read_payload()
            .await?
            .ok_or_else(|| anyhow!("Shadowsocks connection closed before target address"))?;
        let (target_addr, initial_payload) = decode_target(&first_payload)?;

        log::info!(peer = %peer_addr, target = %target_addr.to_key(), "Shadowsocks connecting to target");
        let remote_addrs = target_addr.resolve_socket_addrs().await?;
        let (remote_stream, remote_addr) =
            connect_first_available(&peer_addr, &remote_addrs).await?;
        log::info!(peer = %peer_addr, remote = %remote_addr, "Shadowsocks connected to remote server");

        match relay(client_reader, client_writer, remote_stream, initial_payload).await {
            Ok(true) => Ok(()),
            Ok(false) => {
                log::warn!(peer = %peer_addr, "Shadowsocks connection timeout due to inactivity");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct AeadCipher {
    cipher: Aes256Gcm,
    nonce: [u8; NONCE_LEN],
}

impl AeadCipher {
    fn new(master_key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Self {
        let hkdf = Hkdf::<Sha1>::new(Some(salt), master_key);
        let mut subkey = [0u8; KEY_LEN];
        hkdf.expand(SUBKEY_INFO, &mut subkey)
            .expect("aes-256-gcm subkey length is valid");

        Self {
            cipher: Aes256Gcm::new_from_slice(&subkey)
                .expect("aes-256-gcm key has the required 32-byte length"),
            nonce: [0u8; NONCE_LEN],
        }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&self.nonce), b"", &mut output)
            .map_err(|_| invalid_data("Shadowsocks AEAD encryption failed"))?;
        output.extend_from_slice(&tag);
        self.increment_nonce();
        Ok(output)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(invalid_data(
                "Shadowsocks AEAD frame is shorter than its tag",
            ));
        }

        let payload_len = ciphertext.len() - TAG_LEN;
        let mut output = ciphertext[..payload_len].to_vec();
        let tag = Tag::from_slice(&ciphertext[payload_len..]);
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(&self.nonce), b"", &mut output, tag)
            .map_err(|_| invalid_data("Shadowsocks AEAD authentication failed"))?;
        self.increment_nonce();
        Ok(output)
    }

    fn increment_nonce(&mut self) {
        for byte in &mut self.nonce {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
}

struct Reader<R> {
    stream: R,
    master_key: [u8; KEY_LEN],
    cipher: Option<AeadCipher>,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    fn new(stream: R, master_key: [u8; KEY_LEN]) -> Self {
        Self {
            stream,
            master_key,
            cipher: None,
        }
    }

    async fn read_payload(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.cipher.is_none() {
            let mut salt = [0u8; SALT_LEN];
            if !read_exact_or_eof(&mut self.stream, &mut salt).await? {
                return Ok(None);
            }
            self.cipher = Some(AeadCipher::new(&self.master_key, &salt));
        }

        let mut encrypted_length = [0u8; 2 + TAG_LEN];
        if !read_exact_or_eof(&mut self.stream, &mut encrypted_length).await? {
            return Ok(None);
        }

        let cipher = self
            .cipher
            .as_mut()
            .expect("cipher is initialized after receiving a salt");
        let length = cipher.decrypt(&encrypted_length)?;
        if length.len() != 2 {
            return Err(invalid_data("Shadowsocks encrypted length is invalid"));
        }
        let payload_len = u16::from_be_bytes([length[0], length[1]]) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(invalid_data("Shadowsocks payload exceeds the AEAD limit"));
        }

        let mut encrypted_payload = vec![0u8; payload_len + TAG_LEN];
        read_exact_required(&mut self.stream, &mut encrypted_payload).await?;
        let payload = cipher.decrypt(&encrypted_payload)?;
        if payload.len() != payload_len {
            return Err(invalid_data(
                "Shadowsocks decrypted payload length is invalid",
            ));
        }
        Ok(Some(payload))
    }
}

struct Writer<W> {
    stream: W,
    master_key: [u8; KEY_LEN],
    cipher: Option<AeadCipher>,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    fn new(stream: W, master_key: [u8; KEY_LEN]) -> Self {
        Self {
            stream,
            master_key,
            cipher: None,
        }
    }

    async fn write_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() {
            return Ok(());
        }

        self.initialize_cipher().await?;
        for chunk in payload.chunks(MAX_PAYLOAD_LEN) {
            let cipher = self
                .cipher
                .as_mut()
                .expect("cipher is initialized before encrypted writes");
            let encrypted_length = cipher.encrypt(&(chunk.len() as u16).to_be_bytes())?;
            let encrypted_payload = cipher.encrypt(chunk)?;
            self.stream.write_all(&encrypted_length).await?;
            self.stream.write_all(&encrypted_payload).await?;
        }
        self.stream.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    async fn initialize_cipher(&mut self) -> io::Result<()> {
        if self.cipher.is_some() {
            return Ok(());
        }

        let mut salt = [0u8; SALT_LEN];
        random_fill(&mut salt).map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to generate Shadowsocks salt: {error}"),
            )
        })?;
        self.stream.write_all(&salt).await?;
        self.cipher = Some(AeadCipher::new(&self.master_key, &salt));
        Ok(())
    }
}

async fn relay<R, W>(
    client_reader: Reader<R>,
    client_writer: Writer<W>,
    remote_stream: TcpStream,
    initial_payload: &[u8],
) -> io::Result<bool>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let start_time = Instant::now();
    let last_activity = Arc::new(AtomicU64::new(0));
    let (mut remote_read, mut remote_write) = remote_stream.into_split();

    if !initial_payload.is_empty() {
        remote_write.write_all(initial_payload).await?;
        mark_activity(&last_activity, start_time);
    }

    let client_to_remote_activity = Arc::clone(&last_activity);
    let client_to_remote = async move {
        let mut client_reader = client_reader;
        loop {
            match client_reader.read_payload().await? {
                Some(payload) => {
                    if !payload.is_empty() {
                        remote_write.write_all(&payload).await?;
                        mark_activity(&client_to_remote_activity, start_time);
                    }
                }
                None => {
                    remote_write.shutdown().await?;
                    return Ok::<(), io::Error>(());
                }
            }
        }
    };

    let remote_to_client_activity = Arc::clone(&last_activity);
    let remote_to_client = async move {
        let mut client_writer = client_writer;
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let read = remote_read.read(&mut buffer).await?;
            if read == 0 {
                client_writer.shutdown().await?;
                return Ok::<(), io::Error>(());
            }
            client_writer.write_payload(&buffer[..read]).await?;
            mark_activity(&remote_to_client_activity, start_time);
        }
    };

    let transfer = async { tokio::try_join!(client_to_remote, remote_to_client).map(|_| ()) };
    tokio::pin!(transfer);

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(IDLE_CHECK_SECS));
    interval.tick().await;
    loop {
        tokio::select! {
            result = &mut transfer => {
                result?;
                return Ok(true);
            }
            _ = interval.tick() => {
                let idle_secs = start_time.elapsed().as_secs().saturating_sub(
                    last_activity.load(Ordering::Relaxed),
                );
                if idle_secs >= CONNECTION_TIMEOUT_SECS {
                    return Ok(false);
                }
            }
        }
    }
}

fn decode_target(payload: &[u8]) -> Result<(socks5::Address, &[u8])> {
    let atyp = *payload
        .first()
        .ok_or_else(|| anyhow!("Shadowsocks request is missing address type"))?;
    let mut cursor = 1;

    let address = match atyp {
        1 => {
            let bytes = take(payload, &mut cursor, 6)?;
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&bytes[..4]);
            socks5::Address::IPv4(ip, u16::from_be_bytes([bytes[4], bytes[5]]))
        }
        3 => {
            let domain_len = *take(payload, &mut cursor, 1)?
                .first()
                .expect("one byte was requested") as usize;
            let domain_bytes = take(payload, &mut cursor, domain_len)?;
            let domain = std::str::from_utf8(domain_bytes)
                .map_err(|error| anyhow!("Shadowsocks domain is not valid UTF-8: {error}"))?
                .to_owned();
            let port = take(payload, &mut cursor, 2)?;
            socks5::Address::Domain(domain, u16::from_be_bytes([port[0], port[1]]))
        }
        4 => {
            let bytes = take(payload, &mut cursor, 18)?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[..16]);
            socks5::Address::IPv6(ip, u16::from_be_bytes([bytes[16], bytes[17]]))
        }
        _ => return Err(anyhow!("Unsupported Shadowsocks address type: {atyp}")),
    };

    Ok((address, &payload[cursor..]))
}

fn take<'a>(payload: &'a [u8], cursor: &mut usize, amount: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(amount)
        .ok_or_else(|| anyhow!("Shadowsocks request length overflow"))?;
    let result = payload
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("Shadowsocks request is truncated"))?;
    *cursor = end;
    Ok(result)
}

fn evp_bytes_to_key(password: &str) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let mut previous = Vec::new();
    let mut written = 0;

    while written < key.len() {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password.as_bytes());
        previous = hasher.finalize().to_vec();

        let amount = (key.len() - written).min(previous.len());
        key[written..written + amount].copy_from_slice(&previous[..amount]);
        written += amount;
    }
    key
}

async fn read_exact_or_eof<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = reader.read(&mut buffer[filled..]).await?;
        if read == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Shadowsocks frame ended before completion",
            ));
        }
        filled += read;
    }
    Ok(true)
}

async fn read_exact_required<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> io::Result<()> {
    if read_exact_or_eof(reader, buffer).await? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Shadowsocks frame ended before completion",
        ))
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn mark_activity(last_activity: &AtomicU64, start_time: Instant) {
    last_activity.store(start_time.elapsed().as_secs(), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_cipher_round_trip_preserves_nonce_sequence() {
        let master_key = evp_bytes_to_key("test-password");
        let salt = [0x11; SALT_LEN];
        let mut encryptor = AeadCipher::new(&master_key, &salt);
        let mut decryptor = AeadCipher::new(&master_key, &salt);

        let first = encryptor.encrypt(b"first frame").unwrap();
        let second = encryptor.encrypt(b"second frame").unwrap();

        assert_eq!(decryptor.decrypt(&first).unwrap(), b"first frame");
        assert_eq!(decryptor.decrypt(&second).unwrap(), b"second frame");
    }

    #[test]
    fn decode_target_keeps_initial_payload() {
        let request = [
            3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1, 187, 1, 2,
            3,
        ];
        let (address, payload) = decode_target(&request).unwrap();

        assert_eq!(address.to_key(), "example.com:443");
        assert_eq!(payload, [1, 2, 3]);
    }

    #[tokio::test]
    async fn tcp_aead_codec_round_trip() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let master_key = evp_bytes_to_key("test-password");
        let sender = tokio::spawn(async move {
            let mut writer = Writer::new(client, master_key);
            writer.write_payload(b"hello").await.unwrap();
            writer.write_payload(b"world").await.unwrap();
        });

        let mut reader = Reader::new(server, master_key);
        assert_eq!(reader.read_payload().await.unwrap().unwrap(), b"hello");
        assert_eq!(reader.read_payload().await.unwrap().unwrap(), b"world");
        sender.await.unwrap();
    }
}
