//! Shadowsocks TCP inbound support for the legacy `none` mode and the
//! standard AEAD stream format described by SIP004.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

use crate::{connect_first_available, logger::log, socks5::Address};

const AEAD_TAG_LEN: usize = 16;
const MAX_AEAD_CHUNK_LEN: usize = 0x3fff;
const REQUEST_HEADER_TIMEOUT_SECS: u64 = 15;

/// The Shadowsocks methods supported by this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    None,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

impl Method {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20IetfPoly1305),
            _ => Err(anyhow!(
                "unsupported Shadowsocks method {value:?}; supported methods are none, aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305"
            )),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20IetfPoly1305 => 32,
        }
    }
}

/// A parsed Shadowsocks method and its password-derived master key.
#[derive(Clone)]
pub struct Cipher {
    method: Method,
    master_key: Vec<u8>,
}

impl Cipher {
    pub fn new(method: &str, password: &str) -> Result<Self> {
        let method = Method::parse(method)?;
        let master_key = evp_bytes_to_key(password.as_bytes(), method.key_len());
        Ok(Self { method, master_key })
    }

    fn make_aead(&self, salt: &[u8]) -> Result<AeadCipher> {
        debug_assert_ne!(self.method, Method::None);
        if salt.len() != self.method.key_len() {
            return Err(anyhow!("invalid Shadowsocks AEAD salt length"));
        }

        let hkdf = hkdf::Hkdf::<Sha1>::new(Some(salt), &self.master_key);
        let mut session_key = vec![0u8; self.method.key_len()];
        hkdf.expand(b"ss-subkey", &mut session_key)
            .map_err(|_| anyhow!("failed to derive Shadowsocks AEAD session key"))?;
        AeadCipher::new(self.method, &session_key)
    }

    fn new_salt(&self) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; self.method.key_len()];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| anyhow!("unable to obtain random bytes for Shadowsocks salt"))?;
        Ok(salt)
    }
}

enum AeadCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha20(ChaCha20Poly1305),
}

impl AeadCipher {
    fn new(method: Method, key: &[u8]) -> Result<Self> {
        match method {
            Method::Aes128Gcm => Ok(Self::Aes128(
                Aes128Gcm::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid aes-128-gcm Shadowsocks key"))?,
            )),
            Method::Aes256Gcm => Ok(Self::Aes256(
                Aes256Gcm::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid aes-256-gcm Shadowsocks key"))?,
            )),
            Method::ChaCha20IetfPoly1305 => Ok(Self::ChaCha20(
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| anyhow!("invalid chacha20-ietf-poly1305 Shadowsocks key"))?,
            )),
            Method::None => Err(anyhow!("none is not an AEAD cipher")),
        }
    }

    fn encrypt(&self, nonce: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_bytes(nonce);
        let nonce = Nonce::from_slice(&nonce);
        match self {
            Self::Aes128(cipher) => cipher.encrypt(nonce, plaintext),
            Self::Aes256(cipher) => cipher.encrypt(nonce, plaintext),
            Self::ChaCha20(cipher) => cipher.encrypt(nonce, plaintext),
        }
        .map_err(|_| anyhow!("Shadowsocks AEAD encryption failed"))
    }

    fn decrypt(&self, nonce: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_bytes(nonce);
        let nonce = Nonce::from_slice(&nonce);
        match self {
            Self::Aes128(cipher) => cipher.decrypt(nonce, ciphertext),
            Self::Aes256(cipher) => cipher.decrypt(nonce, ciphertext),
            Self::ChaCha20(cipher) => cipher.decrypt(nonce, ciphertext),
        }
        .map_err(|_| anyhow!("Shadowsocks AEAD authentication failed"))
    }
}

fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Implements the legacy Shadowsocks EVP_BytesToKey password expansion used
/// by all methods supported here.
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        previous = digest.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

/// Process a Shadowsocks byte stream after any configured outer transport has
/// completed. It is used directly for TCP and inside WebSocket or gRPC streams.
pub async fn handle_connection<S>(cipher: Cipher, mut stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match cipher.method {
        Method::None => {
            let address = timeout(
                Duration::from_secs(REQUEST_HEADER_TIMEOUT_SECS),
                read_plain_address(&mut stream),
            )
            .await
            .map_err(|_| anyhow!("Timed out waiting for Shadowsocks request header"))??;
            relay_plain(stream, address, peer_addr).await
        }
        _ => {
            let (address, initial_payload, decryptor, read_nonce) = timeout(
                Duration::from_secs(REQUEST_HEADER_TIMEOUT_SECS),
                read_aead_request(&mut stream, &cipher),
            )
            .await
            .map_err(|_| anyhow!("Timed out waiting for Shadowsocks request header"))??;
            relay_aead(
                stream,
                cipher,
                address,
                initial_payload,
                decryptor,
                read_nonce,
                peer_addr,
            )
            .await
        }
    }
}

async fn relay_plain<S>(mut stream: S, address: Address, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut remote = connect_target(&address, &peer_addr).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn read_aead_request<S>(
    stream: &mut S,
    cipher: &Cipher,
) -> Result<(Address, Vec<u8>, AeadCipher, u64)>
where
    S: AsyncRead + Unpin,
{
    let mut salt = vec![0u8; cipher.method.key_len()];
    stream.read_exact(&mut salt).await?;
    let decryptor = cipher.make_aead(&salt)?;
    let mut nonce = 0;
    let mut header = Vec::new();

    // The target header is at most 259 bytes. A small bounded loop also
    // prevents an unauthenticated peer from holding the connection forever
    // with empty AEAD records.
    for _ in 0..8 {
        let chunk = read_aead_chunk(stream, &decryptor, &mut nonce)
            .await?
            .ok_or_else(|| anyhow!("connection closed before Shadowsocks request header"))?;
        header.extend_from_slice(&chunk);
        if header.len() > 4096 {
            return Err(anyhow!("Shadowsocks request header is too large"));
        }
        if let Some((address, consumed)) = decode_address(&header)? {
            return Ok((address, header.split_off(consumed), decryptor, nonce));
        }
    }

    Err(anyhow!("incomplete Shadowsocks request header"))
}

async fn relay_aead<S>(
    stream: S,
    cipher: Cipher,
    address: Address,
    initial_payload: Vec<u8>,
    decryptor: AeadCipher,
    read_nonce: u64,
    peer_addr: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let remote = connect_target(&address, &peer_addr).await?;
    let response_salt = cipher.new_salt()?;
    let encryptor = cipher.make_aead(&response_salt)?;

    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    if !initial_payload.is_empty() {
        remote_writer.write_all(&initial_payload).await?;
    }
    // The response salt is the first bytes the client expects from the server.
    client_writer.write_all(&response_salt).await?;

    let upload = async move {
        let decryptor = decryptor;
        let mut nonce = read_nonce;
        while let Some(chunk) = read_aead_chunk(&mut client_reader, &decryptor, &mut nonce).await? {
            if !chunk.is_empty() {
                remote_writer.write_all(&chunk).await?;
            }
        }
        remote_writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let download = async move {
        let encryptor = encryptor;
        let mut nonce = 0;
        let mut buffer = vec![0u8; MAX_AEAD_CHUNK_LEN];
        loop {
            let n = remote_reader.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            write_aead_chunk(&mut client_writer, &encryptor, &mut nonce, &buffer[..n]).await?;
        }
        client_writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    // `try_join!` deliberately preserves TCP half-close semantics: a client
    // that closes its write half may still receive the target's final reply.
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn connect_target(address: &Address, peer_addr: &str) -> Result<TcpStream> {
    log::info!(peer = %peer_addr, "Shadowsocks connecting to target");
    let remote_addrs = address.resolve_socket_addrs().await?;
    let (stream, _remote_addr) = connect_first_available(peer_addr, &remote_addrs).await?;
    log::info!(peer = %peer_addr, "Shadowsocks connected to remote server");
    Ok(stream)
}

async fn read_aead_chunk<S>(
    stream: &mut S,
    cipher: &AeadCipher,
    nonce: &mut u64,
) -> Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    if stream.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut encrypted_len = vec![0u8; 2 + AEAD_TAG_LEN];
    encrypted_len[0] = first[0];
    stream.read_exact(&mut encrypted_len[1..]).await?;
    let len = cipher.decrypt(next_nonce(nonce)?, &encrypted_len)?;
    if len.len() != 2 {
        return Err(anyhow!("invalid Shadowsocks AEAD length record"));
    }
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    if len > MAX_AEAD_CHUNK_LEN {
        return Err(anyhow!("Shadowsocks AEAD chunk exceeds 16383 bytes"));
    }

    let mut encrypted_payload = vec![0u8; len + AEAD_TAG_LEN];
    stream.read_exact(&mut encrypted_payload).await?;
    cipher
        .decrypt(next_nonce(nonce)?, &encrypted_payload)
        .map(Some)
}

async fn write_aead_chunk<S>(
    stream: &mut S,
    cipher: &AeadCipher,
    nonce: &mut u64,
    payload: &[u8],
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.len() > MAX_AEAD_CHUNK_LEN {
        return Err(anyhow!("Shadowsocks AEAD chunk exceeds 16383 bytes"));
    }
    let encrypted_len =
        cipher.encrypt(next_nonce(nonce)?, &(payload.len() as u16).to_be_bytes())?;
    let encrypted_payload = cipher.encrypt(next_nonce(nonce)?, payload)?;
    stream.write_all(&encrypted_len).await?;
    stream.write_all(&encrypted_payload).await?;
    Ok(())
}

fn next_nonce(nonce: &mut u64) -> Result<u64> {
    let current = *nonce;
    *nonce = nonce
        .checked_add(1)
        .ok_or_else(|| anyhow!("Shadowsocks AEAD nonce exhausted"))?;
    Ok(current)
}

async fn read_plain_address<S>(stream: &mut S) -> Result<Address>
where
    S: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        1 => {
            let mut bytes = [0u8; 6];
            stream.read_exact(&mut bytes).await?;
            Ok(Address::IPv4(
                bytes[..4].try_into().expect("length is fixed"),
                u16::from_be_bytes([bytes[4], bytes[5]]),
            ))
        }
        4 => {
            let mut bytes = [0u8; 18];
            stream.read_exact(&mut bytes).await?;
            Ok(Address::IPv6(
                bytes[..16].try_into().expect("length is fixed"),
                u16::from_be_bytes([bytes[16], bytes[17]]),
            ))
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut bytes = vec![0u8; length[0] as usize + 2];
            stream.read_exact(&mut bytes).await?;
            let domain = std::str::from_utf8(&bytes[..bytes.len() - 2])
                .map_err(|_| anyhow!("Shadowsocks domain is not valid UTF-8"))?
                .to_string();
            if domain.is_empty() {
                return Err(anyhow!("Shadowsocks domain cannot be empty"));
            }
            let port = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
            Ok(Address::Domain(domain, port))
        }
        _ => Err(anyhow!("invalid Shadowsocks address type")),
    }
}

fn decode_address(buffer: &[u8]) -> Result<Option<(Address, usize)>> {
    let Some(&atyp) = buffer.first() else {
        return Ok(None);
    };
    match atyp {
        1 if buffer.len() >= 7 => Ok(Some((
            Address::IPv4(
                buffer[1..5].try_into().expect("length checked"),
                u16::from_be_bytes([buffer[5], buffer[6]]),
            ),
            7,
        ))),
        4 if buffer.len() >= 19 => Ok(Some((
            Address::IPv6(
                buffer[1..17].try_into().expect("length checked"),
                u16::from_be_bytes([buffer[17], buffer[18]]),
            ),
            19,
        ))),
        3 => {
            if buffer.len() < 2 {
                return Ok(None);
            }
            let domain_len = buffer[1] as usize;
            let total_len = 1 + 1 + domain_len + 2;
            if buffer.len() < total_len {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&buffer[2..2 + domain_len])
                .map_err(|_| anyhow!("Shadowsocks domain is not valid UTF-8"))?
                .to_string();
            if domain.is_empty() {
                return Err(anyhow!("Shadowsocks domain cannot be empty"));
            }
            Ok(Some((
                Address::Domain(
                    domain,
                    u16::from_be_bytes([buffer[2 + domain_len], buffer[3 + domain_len]]),
                ),
                total_len,
            )))
        }
        1 | 4 => Ok(None),
        _ => Err(anyhow!("invalid Shadowsocks address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn supported_methods_parse_case_insensitively() {
        assert_eq!(Method::parse("AES-128-GCM").unwrap(), Method::Aes128Gcm);
        assert!(Method::parse("rc4-md5").is_err());
    }

    #[test]
    fn aead_round_trip_uses_independent_nonce_counters() {
        let cipher = Cipher::new("chacha20-ietf-poly1305", "password").unwrap();
        let salt = vec![7u8; 32];
        let encryptor = cipher.make_aead(&salt).unwrap();
        let decryptor = cipher.make_aead(&salt).unwrap();
        let mut write_nonce = 0;
        let mut read_nonce = 0;

        let encrypted_len = encryptor
            .encrypt(next_nonce(&mut write_nonce).unwrap(), &[0, 3])
            .unwrap();
        let encrypted_payload = encryptor
            .encrypt(next_nonce(&mut write_nonce).unwrap(), b"abc")
            .unwrap();
        assert_eq!(
            decryptor
                .decrypt(next_nonce(&mut read_nonce).unwrap(), &encrypted_len)
                .unwrap(),
            [0, 3]
        );
        assert_eq!(
            decryptor
                .decrypt(next_nonce(&mut read_nonce).unwrap(), &encrypted_payload)
                .unwrap(),
            b"abc"
        );
    }

    #[test]
    fn address_decoder_preserves_payload() {
        let request = [3, 3, b'f', b'o', b'o', 0x01, 0xbb, b'x'];
        let (address, consumed) = decode_address(&request).unwrap().unwrap();
        assert_eq!(address.to_key(), "foo:443");
        assert_eq!(&request[consumed..], b"x");
    }

    #[tokio::test]
    async fn aead_tcp_relay_interoperates_with_a_standard_framed_client() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buffer = [0u8; 32];
            let n = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..n]).await.unwrap();
        });

        let ss_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ss_addr = ss_listener.local_addr().unwrap();
        let server_cipher = Cipher::new("aes-256-gcm", "test-password").unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = ss_listener.accept().await.unwrap();
            handle_connection(server_cipher, stream, peer.to_string()).await
        });

        let client_cipher = Cipher::new("aes-256-gcm", "test-password").unwrap();
        let request_salt = vec![9u8; 32];
        let encryptor = client_cipher.make_aead(&request_salt).unwrap();
        let mut write_nonce = 0;
        let mut client = TcpStream::connect(ss_addr).await.unwrap();
        client.write_all(&request_salt).await.unwrap();
        let mut request = vec![1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        request.extend_from_slice(b"ping");
        write_aead_chunk(&mut client, &encryptor, &mut write_nonce, &request)
            .await
            .unwrap();

        let mut response_salt = vec![0u8; 32];
        timeout(
            Duration::from_secs(2),
            client.read_exact(&mut response_salt),
        )
        .await
        .unwrap()
        .unwrap();
        let decryptor = client_cipher.make_aead(&response_salt).unwrap();
        let mut read_nonce = 0;
        let response = timeout(
            Duration::from_secs(2),
            read_aead_chunk(&mut client, &decryptor, &mut read_nonce),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(response, b"ping");

        drop(client);
        echo_task.await.unwrap();
        server_task.await.unwrap().unwrap();
    }
}
