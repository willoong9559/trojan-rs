//! VMess AEAD (`alterId = 0`) inbound implementation.
//!
//! VMess authenticates its request header independently from the outer
//! transport and then uses separately keyed AEAD records in each direction.
//! This module deliberately accepts only the modern AEAD form: legacy
//! alter-ID users are deprecated by Xray and cannot be authenticated without
//! retaining a large set of rotating IDs.

use std::{
    cmp, io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{Block, BlockDecrypt, KeyInit},
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

/// Parse the AEAD request header and produce a decrypted bidirectional stream.
pub async fn accept<S>(mut stream: S, user_id: [u8; 16]) -> Result<Accepted<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut auth_id = [0; 16];
    stream.read_exact(&mut auth_id).await?;
    verify_auth_id(&user_id, auth_id)?;
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
}
