//! VMess inbound implementation, including modern AEAD and legacy alter-ID
//! request headers.

use std::{
    cmp,
    collections::HashMap,
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use chacha20poly1305::ChaCha20Poly1305;
use crc32fast::hash as crc32;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::socks5;

const HEADER_MAX_LEN: usize = 1024;
const MAX_CHUNK_LEN: usize = 16 * 1024;
const AUTH_ID_MAX_TIME_DIFF_SECS: u64 = 120;
const LEGACY_AUTH_CACHE_REFRESH_SECS: u64 = 10;
pub const MAX_LEGACY_ALTER_ID: u16 = 256;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const OPTION_GLOBAL_PADDING: u8 = 0x08;
const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
// These are Xray's current `protocol.SecurityType` values. VMess's original
// public description used 0x02 and 0x03, but Xray has reserved 0x02 and emits
// 0x03 (AES-GCM) / 0x04 (ChaCha20-Poly1305) on the wire.
const SECURITY_AES_128_GCM: u8 = 0x03;
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;

const KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const KDF_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const KDF_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const KDF_RESPONSE_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_RESPONSE_LEN_NONCE: &[u8] = b"AEAD Resp Header Len IV";
const KDF_RESPONSE_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_RESPONSE_NONCE: &[u8] = b"AEAD Resp Header IV";
const ALTER_ID_SALT: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
const ALTER_ID_REHASH_SALT: &[u8] = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2";

type HmacMd5 = Hmac<Md5>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub struct Request {
    pub command: Command,
    pub addr: socks5::Address,
}

#[derive(Clone)]
enum HashState {
    Sha256(Sha256),
    Hmac(RecursiveHmac),
}

/// HMAC whose underlying hash can itself be an HMAC. VMess's KDF relies on
/// this recursive construction, rather than ordinary HMAC-SHA256 chaining.
#[derive(Clone)]
struct RecursiveHmac {
    inner: Box<HashState>,
    outer: Box<HashState>,
    outer_pad: [u8; 64],
}

impl HashState {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hash) => Sha2Digest::update(hash, data),
            Self::Hmac(hash) => hash.update(data),
        }
    }

    fn finalize(&self) -> [u8; 32] {
        match self {
            Self::Sha256(hash) => {
                let digest = Sha2Digest::finalize(hash.clone());
                digest.into()
            }
            Self::Hmac(hash) => hash.finalize(),
        }
    }
}

impl RecursiveHmac {
    fn new(key: &[u8], hash: HashState) -> Self {
        // All VMess KDF path elements are short. Hashing an overlong key here
        // would not match the reference implementation, so reject it instead.
        debug_assert!(key.len() <= 64);
        let mut inner_pad = [0x36; 64];
        let mut outer_pad = [0x5c; 64];
        for (index, value) in key.iter().copied().enumerate() {
            inner_pad[index] ^= value;
            outer_pad[index] ^= value;
        }
        let mut inner = hash.clone();
        inner.update(&inner_pad);
        Self {
            inner: Box::new(inner),
            outer: Box::new(hash),
            outer_pad,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(&self) -> [u8; 32] {
        let mut outer = (*self.outer).clone();
        outer.update(&self.outer_pad);
        outer.update(&self.inner.finalize());
        outer.finalize()
    }
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut current = HashState::Hmac(RecursiveHmac::new(
        KDF_ROOT,
        HashState::Sha256(Sha256::new()),
    ));
    for part in path {
        current = HashState::Hmac(RecursiveHmac::new(part, current));
    }
    current.update(key);
    current.finalize()
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let output = kdf(key, path);
    output[..16].try_into().expect("KDF output is 32 bytes")
}

fn command_key(user_id: &[u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    Md5Digest::update(&mut hash, user_id);
    Md5Digest::update(&mut hash, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hash.finalize().into()
}

fn next_alter_id(user_id: &[u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    Md5Digest::update(&mut hash, user_id);
    Md5Digest::update(&mut hash, ALTER_ID_SALT);
    let next: [u8; 16] = hash.clone().finalize().into();
    if &next != user_id {
        return next;
    }

    // Match V2Ray's exceedingly rare collision fallback exactly.
    Md5Digest::update(&mut hash, ALTER_ID_REHASH_SALT);
    hash.finalize().into()
}

fn legacy_auth_id(user_id: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(user_id).expect("UUID is a fixed-size HMAC key");
    Mac::update(&mut mac, &timestamp.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn legacy_header_iv(timestamp: u64) -> [u8; 16] {
    let mut hash = Md5::new();
    let timestamp = timestamp.to_be_bytes();
    for _ in 0..4 {
        Md5Digest::update(&mut hash, timestamp);
    }
    hash.finalize().into()
}

/// Matches VMess's rotating legacy alter-ID authentication hashes. The cache
/// covers the same +/- two-minute timestamp window used by VMess AEAD.
pub struct LegacyAuthenticator {
    ids: Vec<[u8; 16]>,
    cache: Mutex<LegacyAuthCache>,
}

struct LegacyAuthCache {
    refreshed_at: u64,
    hashes: HashMap<[u8; 16], u64>,
}

impl LegacyAuthenticator {
    pub fn new(user_id: [u8; 16], alter_id: u16) -> Self {
        let mut ids = Vec::with_capacity(usize::from(alter_id) + 1);
        ids.push(user_id);
        let mut current = user_id;
        for _ in 0..alter_id {
            current = next_alter_id(&current);
            ids.push(current);
        }
        Self {
            ids,
            cache: Mutex::new(LegacyAuthCache {
                refreshed_at: 0,
                hashes: HashMap::new(),
            }),
        }
    }

    fn match_auth_id(&self, auth_id: &[u8; 16]) -> Result<Option<u64>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut cache = self.cache.lock().expect("legacy VMess auth cache poisoned");
        if cache.hashes.is_empty()
            || now < cache.refreshed_at
            || now - cache.refreshed_at >= LEGACY_AUTH_CACHE_REFRESH_SECS
        {
            let start = now.saturating_sub(AUTH_ID_MAX_TIME_DIFF_SECS);
            let end = now.saturating_add(AUTH_ID_MAX_TIME_DIFF_SECS);
            let capacity = self.ids.len().saturating_mul(
                usize::try_from(end.saturating_sub(start).saturating_add(1)).unwrap_or(usize::MAX),
            );
            let mut hashes = HashMap::with_capacity(capacity);
            for timestamp in start..=end {
                for user_id in &self.ids {
                    hashes.insert(legacy_auth_id(user_id, timestamp), timestamp);
                }
            }
            cache.refreshed_at = now;
            cache.hashes = hashes;
        }
        Ok(cache.hashes.get(auth_id).copied())
    }
}

/// Stateful AES-128-CFB used only by VMess's legacy request and response
/// headers. Body encryption remains the configured AEAD stream cipher.
struct AesCfb128 {
    cipher: Aes128,
    feedback: [u8; 16],
    offset: usize,
}

impl AesCfb128 {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new_from_slice(key).expect("fixed AES-128 key length"),
            feedback: *iv,
            offset: 0,
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == 0 {
                let mut block = Block::<Aes128>::clone_from_slice(&self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.feedback.copy_from_slice(&block);
            }
            let ciphertext = *byte;
            *byte ^= self.feedback[self.offset];
            self.feedback[self.offset] = ciphertext;
            self.offset = (self.offset + 1) % self.feedback.len();
        }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.offset == 0 {
                let mut block = Block::<Aes128>::clone_from_slice(&self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.feedback.copy_from_slice(&block);
            }
            *byte ^= self.feedback[self.offset];
            self.feedback[self.offset] = *byte;
            self.offset = (self.offset + 1) % self.feedback.len();
        }
    }
}

fn verify_auth_id(user_id: &[u8; 16], mut auth_id: [u8; 16]) -> Result<[u8; 16]> {
    let key = kdf16(&command_key(user_id), &[KDF_AUTH_ID]);
    let cipher = Aes128::new_from_slice(&key).expect("fixed AES-128 key length");
    let mut block = Block::<Aes128>::clone_from_slice(&auth_id);
    cipher.decrypt_block(&mut block);
    auth_id.copy_from_slice(&block);

    let expected = u32::from_be_bytes(auth_id[12..].try_into().unwrap());
    if crc32(&auth_id[..12]) != expected {
        return Err(anyhow!("invalid VMess authentication ID"));
    }
    let timestamp = u64::from_be_bytes(auth_id[..8].try_into().unwrap());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if now.abs_diff(timestamp) > AUTH_ID_MAX_TIME_DIFF_SECS {
        return Err(anyhow!(
            "VMess authentication timestamp is outside the allowed window"
        ));
    }
    Ok(auth_id)
}

fn decrypt_aes_gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("fixed AES-128 key length");
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("VMess AEAD authentication failed"))
}

fn encrypt_aes_gcm(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("fixed AES-128 key length");
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption with a fixed nonce size cannot fail")
}

fn decode_address(buf: &[u8], cursor: &mut usize) -> Result<socks5::Address> {
    if buf.len() < *cursor + 3 {
        return Err(anyhow!("truncated VMess destination"));
    }
    let port = u16::from_be_bytes([buf[*cursor], buf[*cursor + 1]]);
    *cursor += 2;
    let address = match buf[*cursor] {
        1 => {
            *cursor += 1;
            let bytes: [u8; 4] = buf
                .get(*cursor..*cursor + 4)
                .ok_or_else(|| anyhow!("truncated VMess IPv4 address"))?
                .try_into()
                .unwrap();
            *cursor += 4;
            socks5::Address::IPv4(bytes, port)
        }
        2 => {
            *cursor += 1;
            let length = *buf
                .get(*cursor)
                .ok_or_else(|| anyhow!("truncated VMess domain address"))?
                as usize;
            *cursor += 1;
            if length == 0 {
                return Err(anyhow!("invalid empty VMess domain"));
            }
            let domain = std::str::from_utf8(
                buf.get(*cursor..*cursor + length)
                    .ok_or_else(|| anyhow!("truncated VMess domain address"))?,
            )?
            .to_string();
            *cursor += length;
            socks5::Address::Domain(domain, port)
        }
        3 => {
            *cursor += 1;
            let bytes: [u8; 16] = buf
                .get(*cursor..*cursor + 16)
                .ok_or_else(|| anyhow!("truncated VMess IPv6 address"))?
                .try_into()
                .unwrap();
            *cursor += 16;
            socks5::Address::IPv6(bytes, port)
        }
        kind => return Err(anyhow!("unsupported VMess address type {kind}")),
    };
    Ok(address)
}

#[derive(Clone)]
enum BodyCipher {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl BodyCipher {
    fn new(security: u8, key: &[u8; 16]) -> Result<Self> {
        match security {
            SECURITY_AES_128_GCM => Ok(Self::Aes(Aes128Gcm::new_from_slice(key).unwrap())),
            SECURITY_CHACHA20_POLY1305 => {
                let first = Md5::digest(key);
                let second = Md5::digest(first);
                let mut expanded = [0u8; 32];
                expanded[..16].copy_from_slice(&first);
                expanded[16..].copy_from_slice(&second);
                Ok(Self::ChaCha(
                    ChaCha20Poly1305::new_from_slice(&expanded).unwrap(),
                ))
            }
            _ => Err(anyhow!(
                "unsupported VMess body security {security}; use aes-128-gcm or chacha20-poly1305"
            )),
        }
    }

    fn open(&self, nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Aes(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), data)
                .map_err(|_| anyhow!("VMess body authentication failed")),
            Self::ChaCha(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), data)
                .map_err(|_| anyhow!("VMess body authentication failed")),
        }
    }

    fn seal(&self, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), data)
                .expect("fixed nonce size"),
            Self::ChaCha(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), data)
                .expect("fixed nonce size"),
        }
    }
}

struct Mask {
    reader: Box<dyn XofReader + Send>,
}

impl Mask {
    fn new(iv: &[u8; 16]) -> Self {
        let mut hash = Shake128::default();
        hash.update(iv);
        Self {
            reader: Box::new(hash.finalize_xof()),
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut bytes = [0; 2];
        self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

fn chunk_nonce(iv: &[u8; 16], count: &mut u16) -> [u8; 12] {
    let mut nonce: [u8; 12] = iv[..12].try_into().unwrap();
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    *count = count.wrapping_add(1);
    nonce
}

pub struct Accepted<S> {
    pub request: Request,
    pub stream: Stream<S>,
}

async fn accept_legacy<S>(mut stream: S, user_id: [u8; 16], timestamp: u64) -> Result<Accepted<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let command_key = command_key(&user_id);
    let header_iv = legacy_header_iv(timestamp);
    let mut cfb = AesCfb128::new(&command_key, &header_iv);

    let mut header = vec![0; 38];
    stream.read_exact(&mut header).await?;
    cfb.decrypt(&mut header);
    if header[0] != 1 {
        return Err(anyhow!("unsupported legacy VMess request header"));
    }

    let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let request_key: [u8; 16] = header[17..33].try_into().unwrap();
    let response_auth = header[33];
    let options = header[34];
    let padding_len = (header[35] >> 4) as usize;
    let security = header[35] & 0x0f;
    if options & OPTION_CHUNK_STREAM == 0 {
        return Err(anyhow!("VMess without chunk stream is not supported"));
    }
    if options & OPTION_AUTHENTICATED_LENGTH != 0 {
        return Err(anyhow!("VMess authenticated length is not supported"));
    }
    let command = match header[37] {
        1 => Command::Tcp,
        2 => Command::Udp,
        command => return Err(anyhow!("unsupported VMess command {command}")),
    };

    let mut address_prefix = [0; 3];
    stream.read_exact(&mut address_prefix).await?;
    cfb.decrypt(&mut address_prefix);
    header.extend_from_slice(&address_prefix);
    let address_remaining = match address_prefix[2] {
        1 => 4,
        2 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await?;
            cfb.decrypt(&mut length);
            header.extend_from_slice(&length);
            usize::from(length[0])
        }
        3 => 16,
        kind => return Err(anyhow!("unsupported VMess address type {kind}")),
    };
    let mut address = vec![0; address_remaining];
    stream.read_exact(&mut address).await?;
    cfb.decrypt(&mut address);
    header.extend_from_slice(&address);

    let mut trailer = vec![0; padding_len + 4];
    stream.read_exact(&mut trailer).await?;
    cfb.decrypt(&mut trailer);
    header.extend_from_slice(&trailer);

    let mut cursor = 38;
    let addr = decode_address(&header, &mut cursor)?;
    let checksum_offset = cursor
        .checked_add(padding_len)
        .ok_or_else(|| anyhow!("invalid legacy VMess header padding"))?;
    if checksum_offset + 4 != header.len() {
        return Err(anyhow!("invalid legacy VMess request header size"));
    }
    let expected = u32::from_be_bytes(header[checksum_offset..].try_into().unwrap());
    if fnv1a(&header[..checksum_offset]) != expected {
        return Err(anyhow!("invalid legacy VMess request checksum"));
    }

    let response_key: [u8; 16] = Md5::digest(request_key).into();
    let response_iv: [u8; 16] = Md5::digest(request_iv).into();
    write_legacy_response_header(&mut stream, response_auth, &response_key, &response_iv).await?;

    Ok(Accepted {
        request: Request { command, addr },
        stream: Stream::new(
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            options,
        )?,
    })
}

/// Parse the AEAD request header and produce a decrypted bidirectional stream.
pub async fn accept<S>(
    mut stream: S,
    user_id: [u8; 16],
    legacy_authenticator: Option<&LegacyAuthenticator>,
) -> Result<Accepted<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut auth_id = [0; 16];
    stream.read_exact(&mut auth_id).await?;
    if verify_auth_id(&user_id, auth_id).is_err() {
        let Some(legacy_authenticator) = legacy_authenticator else {
            return Err(anyhow!("invalid VMess authentication ID"));
        };
        let Some(timestamp) = legacy_authenticator.match_auth_id(&auth_id)? else {
            return Err(anyhow!("invalid legacy VMess authentication ID"));
        };
        return accept_legacy(stream, user_id, timestamp).await;
    }
    let command_key = command_key(&user_id);

    let mut encrypted_length = [0; 18];
    stream.read_exact(&mut encrypted_length).await?;
    let mut connection_nonce = [0; 8];
    stream.read_exact(&mut connection_nonce).await?;

    let nonce = kdf(
        &command_key,
        &[KDF_HEADER_LEN_NONCE, &auth_id, &connection_nonce],
    );
    let key = kdf16(
        &command_key,
        &[KDF_HEADER_LEN_KEY, &auth_id, &connection_nonce],
    );
    let header_len = decrypt_aes_gcm(
        &key,
        &nonce[..12].try_into().unwrap(),
        &encrypted_length,
        &auth_id,
    )?;
    if header_len.len() != 2 {
        return Err(anyhow!("invalid VMess AEAD header length"));
    }
    let header_len = u16::from_be_bytes(header_len.try_into().unwrap()) as usize;
    if !(42..=HEADER_MAX_LEN).contains(&header_len) {
        return Err(anyhow!("invalid VMess AEAD header size {header_len}"));
    }
    let mut encrypted_header = vec![0; header_len + 16];
    stream.read_exact(&mut encrypted_header).await?;
    let nonce = kdf(
        &command_key,
        &[KDF_HEADER_NONCE, &auth_id, &connection_nonce],
    );
    let key = kdf16(&command_key, &[KDF_HEADER_KEY, &auth_id, &connection_nonce]);
    let header = decrypt_aes_gcm(
        &key,
        &nonce[..12].try_into().unwrap(),
        &encrypted_header,
        &auth_id,
    )?;

    if header.len() < 42 || header[0] != 1 {
        return Err(anyhow!("unsupported VMess request header"));
    }
    let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let request_key: [u8; 16] = header[17..33].try_into().unwrap();
    let response_auth = header[33];
    let options = header[34];
    let padding_len = (header[35] >> 4) as usize;
    let security = header[35] & 0x0f;
    if options & OPTION_CHUNK_STREAM == 0 {
        return Err(anyhow!("VMess without chunk stream is not supported"));
    }
    if options & OPTION_AUTHENTICATED_LENGTH != 0 {
        return Err(anyhow!("VMess authenticated length is not supported"));
    }
    let command = match header[37] {
        1 => Command::Tcp,
        2 => Command::Udp,
        command => return Err(anyhow!("unsupported VMess command {command}")),
    };
    let mut cursor = 38;
    let addr = decode_address(&header, &mut cursor)?;
    let checksum_offset = cursor
        .checked_add(padding_len)
        .ok_or_else(|| anyhow!("invalid VMess header padding"))?;
    if checksum_offset + 4 != header.len() {
        return Err(anyhow!("invalid VMess request header size"));
    }
    let expected = u32::from_be_bytes(header[checksum_offset..].try_into().unwrap());
    let actual = fnv1a(&header[..checksum_offset]);
    if actual != expected {
        return Err(anyhow!("invalid VMess request checksum"));
    }

    let response_key: [u8; 16] = Sha256::digest(request_key)[..16].try_into().unwrap();
    let response_iv: [u8; 16] = Sha256::digest(request_iv)[..16].try_into().unwrap();
    write_response_header(&mut stream, response_auth, &response_key, &response_iv).await?;

    Ok(Accepted {
        request: Request { command, addr },
        stream: Stream::new(
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
            security,
            options,
        )?,
    })
}

async fn write_response_header<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response_auth: u8,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<()> {
    let header = [response_auth, 0, 0, 0];
    let length = (header.len() as u16).to_be_bytes();
    let len_key = kdf16(key, &[KDF_RESPONSE_LEN_KEY]);
    let len_nonce = kdf(iv, &[KDF_RESPONSE_LEN_NONCE]);
    let data_key = kdf16(key, &[KDF_RESPONSE_KEY]);
    let data_nonce = kdf(iv, &[KDF_RESPONSE_NONCE]);
    stream
        .write_all(&encrypt_aes_gcm(
            &len_key,
            &len_nonce[..12].try_into().unwrap(),
            &length,
            &[],
        ))
        .await?;
    stream
        .write_all(&encrypt_aes_gcm(
            &data_key,
            &data_nonce[..12].try_into().unwrap(),
            &header,
            &[],
        ))
        .await?;
    stream.flush().await?;
    Ok(())
}

async fn write_legacy_response_header<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response_auth: u8,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<()> {
    let mut header = [response_auth, 0, 0, 0];
    AesCfb128::new(key, iv).encrypt(&mut header);
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut value = 0x811c_9dc5u32;
    for byte in bytes {
        value ^= u32::from(*byte);
        value = value.wrapping_mul(0x0100_0193);
    }
    value
}

pub struct Stream<S> {
    inner: S,
    read_cipher: BodyCipher,
    write_cipher: BodyCipher,
    read_iv: [u8; 16],
    write_iv: [u8; 16],
    read_counter: u16,
    write_counter: u16,
    read_mask: Option<Mask>,
    write_mask: Option<Mask>,
    global_padding: bool,
    read_stage: ReadStage,
    read_plaintext: Vec<u8>,
    write_pending: Option<(Vec<u8>, usize)>,
    write_offset: usize,
    closing: bool,
    end_sent: bool,
}

enum ReadStage {
    Length(Vec<u8>),
    Payload {
        encoded_len: usize,
        padding: usize,
        data: Vec<u8>,
    },
    Eof,
}

impl<S> Stream<S> {
    fn new(
        inner: S,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        security: u8,
        options: u8,
    ) -> Result<Self> {
        let masked = options & OPTION_CHUNK_MASKING != 0;
        Ok(Self {
            inner,
            read_cipher: BodyCipher::new(security, &request_key)?,
            write_cipher: BodyCipher::new(security, &response_key)?,
            read_iv: request_iv,
            write_iv: response_iv,
            read_counter: 0,
            write_counter: 0,
            read_mask: masked.then(|| Mask::new(&request_iv)),
            write_mask: masked.then(|| Mask::new(&response_iv)),
            global_padding: options & OPTION_GLOBAL_PADDING != 0,
            read_stage: ReadStage::Length(Vec::with_capacity(2)),
            read_plaintext: Vec::new(),
            write_pending: None,
            write_offset: 0,
            closing: false,
            end_sent: false,
        })
    }

    fn encode_chunk(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = chunk_nonce(&self.write_iv, &mut self.write_counter);
        let ciphertext = self.write_cipher.seal(&nonce, plaintext);
        let padding_len = if self.global_padding {
            self.write_mask
                .as_mut()
                .expect("padding requires masking")
                .next_u16() as usize
                % 64
        } else {
            0
        };
        let total = ciphertext.len() + padding_len;
        if total > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess chunk is too large",
            ));
        }
        let mask = self.write_mask.as_mut().map(Mask::next_u16).unwrap_or(0);
        let mut output = Vec::with_capacity(2 + total);
        output.extend_from_slice(&((total as u16) ^ mask).to_be_bytes());
        output.extend_from_slice(&ciphertext);
        if padding_len > 0 {
            let start = output.len();
            output.resize(start + padding_len, 0);
            SystemRandom::new()
                .fill(&mut output[start..])
                .map_err(|_| io::Error::other("failed to generate VMess padding"))?;
        }
        Ok(output)
    }

    fn poll_fill_exact(
        &mut self,
        cx: &mut Context<'_>,
        target: &mut Vec<u8>,
        len: usize,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        while target.len() < len {
            let remaining = len - target.len();
            let mut scratch = [0u8; 8192];
            let read_len = cmp::min(remaining, scratch.len());
            let mut read_buf = ReadBuf::new(&mut scratch[..read_len]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().is_empty() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VMess stream ended mid-frame",
                        )));
                    }
                    target.extend_from_slice(read_buf.filled());
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream<S> {
    fn poll_next_packet(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            let state = std::mem::replace(&mut self.read_stage, ReadStage::Eof);
            match state {
                ReadStage::Eof => {
                    self.read_stage = ReadStage::Eof;
                    return Poll::Ready(Ok(None));
                }
                ReadStage::Length(mut encoded) => {
                    match self.poll_fill_exact(cx, &mut encoded, 2) {
                        Poll::Pending => {
                            self.read_stage = ReadStage::Length(encoded);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error))
                            if error.kind() == io::ErrorKind::UnexpectedEof
                                && encoded.is_empty() =>
                        {
                            self.read_stage = ReadStage::Eof;
                            return Poll::Ready(Ok(None));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let encoded_len = u16::from_be_bytes(encoded.try_into().unwrap());
                    let padding = if self.global_padding {
                        self.read_mask
                            .as_mut()
                            .expect("padding requires masking")
                            .next_u16() as usize
                            % 64
                    } else {
                        0
                    };
                    let mask = self.read_mask.as_mut().map(Mask::next_u16).unwrap_or(0);
                    let encoded_len = (encoded_len ^ mask) as usize;
                    if encoded_len < 16 + padding || encoded_len > MAX_CHUNK_LEN + 16 + 63 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid VMess chunk length",
                        )));
                    }
                    self.read_stage = ReadStage::Payload {
                        encoded_len,
                        padding,
                        data: Vec::with_capacity(encoded_len),
                    };
                }
                ReadStage::Payload {
                    encoded_len,
                    padding,
                    mut data,
                } => {
                    match self.poll_fill_exact(cx, &mut data, encoded_len) {
                        Poll::Pending => {
                            self.read_stage = ReadStage::Payload {
                                encoded_len,
                                padding,
                                data,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let ciphertext_len = encoded_len - padding;
                    let read_iv = self.read_iv;
                    let nonce = chunk_nonce(&read_iv, &mut self.read_counter);
                    let plaintext = self
                        .read_cipher
                        .open(&nonce, &data[..ciphertext_len])
                        .map_err(io::Error::other)?;
                    self.read_stage = ReadStage::Length(Vec::with_capacity(2));
                    if plaintext.is_empty() {
                        self.read_stage = ReadStage::Eof;
                        return Poll::Ready(Ok(None));
                    }
                    return Poll::Ready(Ok(Some(plaintext)));
                }
            }
        }
    }

    /// Receive one VMess record. VMess UDP defines one datagram per record.
    pub async fn read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next_packet(cx)).await
    }

    /// Send one VMess UDP record without coalescing it with another datagram.
    pub async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > MAX_CHUNK_LEN - 16 - 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess UDP packet is too large",
            ));
        }
        self.write_all(packet).await?;
        self.flush().await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_plaintext.is_empty() {
                let length = cmp::min(out.remaining(), self.read_plaintext.len());
                out.put_slice(&self.read_plaintext[..length]);
                self.read_plaintext.drain(..length);
                return Poll::Ready(Ok(()));
            }
            match self.as_mut().poll_next_packet(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(packet))) => self.read_plaintext = packet,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VMess stream is shutting down",
            )));
        }
        if self.write_pending.is_none() {
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let length = cmp::min(input.len(), MAX_CHUNK_LEN - 16 - 63);
            let frame = self.encode_chunk(&input[..length])?;
            self.write_pending = Some((frame, length));
            self.write_offset = 0;
        }
        loop {
            let (frame_len, pending) = {
                let (frame, _) = self.write_pending.as_ref().unwrap();
                (frame.len(), frame[self.write_offset..].to_vec())
            };
            if self.write_offset == frame_len {
                break;
            }
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write VMess frame",
                    )))
                }
                Poll::Ready(Ok(length)) => self.write_offset += length,
            }
        }
        let written = self.write_pending.as_ref().unwrap().1;
        self.write_pending = None;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_pending.is_some() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closing = true;
        if !self.end_sent {
            if self.write_pending.is_none() {
                let frame = self.encode_chunk(&[])?;
                self.write_pending = Some((frame, 0));
                self.write_offset = 0;
            }
            loop {
                let (frame_len, pending) = {
                    let (frame, _) = self.write_pending.as_ref().unwrap();
                    (frame.len(), frame[self.write_offset..].to_vec())
                };
                if self.write_offset == frame_len {
                    break;
                }
                match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write VMess termination frame",
                        )))
                    }
                    Poll::Ready(Ok(length)) => self.write_offset += length,
                }
            }
            self.write_pending = None;
            self.end_sent = true;
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn legacy_request(
        user_id: [u8; 16],
        alter_id: u16,
        timestamp: u64,
        request_iv: [u8; 16],
        request_key: [u8; 16],
        response_auth: u8,
    ) -> Vec<u8> {
        let mut selected_id = user_id;
        for _ in 0..alter_id {
            selected_id = next_alter_id(&selected_id);
        }

        let mut header = Vec::with_capacity(48);
        header.push(1);
        header.extend_from_slice(&request_iv);
        header.extend_from_slice(&request_key);
        header.push(response_auth);
        header.push(OPTION_CHUNK_STREAM);
        header.push(SECURITY_AES_128_GCM);
        header.push(0);
        header.push(1);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&fnv1a(&header).to_be_bytes());

        let command_key = command_key(&user_id);
        AesCfb128::new(&command_key, &legacy_header_iv(timestamp)).encrypt(&mut header);
        let mut wire = legacy_auth_id(&selected_id, timestamp).to_vec();
        wire.extend_from_slice(&header);
        wire
    }

    #[test]
    fn vmess_kdf_is_stable() {
        assert_eq!(
            kdf(b"test-key", &[KDF_AUTH_ID]),
            kdf(b"test-key", &[KDF_AUTH_ID])
        );
        assert_ne!(
            kdf(b"test-key", &[KDF_AUTH_ID]),
            kdf(b"test-key", &[KDF_HEADER_KEY])
        );
    }

    #[test]
    fn parses_uuid_with_shared_vless_helper() {
        let id = crate::vless::parse_uuid("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_ne!(command_key(&id), [0; 16]);
    }

    #[test]
    fn aes_cfb128_matches_the_nist_vector() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ciphertext = hex::decode("3b3fd92eb72dad20333449f8e83cfb4a").unwrap();

        let mut encrypted = plaintext.clone();
        AesCfb128::new(&key, &iv).encrypt(&mut encrypted);
        assert_eq!(encrypted, ciphertext);
        AesCfb128::new(&key, &iv).decrypt(&mut encrypted);
        assert_eq!(encrypted, plaintext);
    }

    #[tokio::test]
    async fn accepts_a_legacy_alter_id_header_and_returns_legacy_response_header() {
        let user_id = *b"0123456789abcdef";
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let request_iv = [0x11; 16];
        let request_key = [0x22; 16];
        let response_auth = 0x5a;
        let request = legacy_request(
            user_id,
            1,
            timestamp,
            request_iv,
            request_key,
            response_auth,
        );
        let authenticator = LegacyAuthenticator::new(user_id, 1);
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(&request).await.unwrap();

        let accepted = accept(server, user_id, Some(&authenticator)).await.unwrap();
        assert_eq!(accepted.request.command, Command::Tcp);
        assert!(matches!(
            accepted.request.addr,
            socks5::Address::IPv4([127, 0, 0, 1], 443)
        ));

        let mut response = [0; 4];
        client.read_exact(&mut response).await.unwrap();
        let response_key: [u8; 16] = Md5::digest(request_key).into();
        let response_iv: [u8; 16] = Md5::digest(request_iv).into();
        AesCfb128::new(&response_key, &response_iv).decrypt(&mut response);
        assert_eq!(response, [response_auth, 0, 0, 0]);
    }
}
