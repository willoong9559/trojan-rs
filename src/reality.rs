//! Server-side REALITY transport.
//!
//! This uses cfal/rustls' narrowly scoped REALITY APIs.  Authentication is
//! completed before any Trojan bytes are exposed; unauthenticated TLS clients
//! are relayed to the configured cover site.

use anyhow::{anyhow, Context, Result};
use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    agreement,
    hkdf::{Salt, HKDF_SHA256},
    hmac,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::{Buf, Bytes};
use rustls::{
    pki_types::CertificateDer,
    sign::{CertifiedKey, Signer, SigningKey},
    SignatureAlgorithm, SignatureScheme,
};
use std::{
    fmt,
    io::{self, BufRead, Read, Write},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{timeout, Duration},
};

use crate::config::RealitySettings;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const TARGET_TIMEOUT: Duration = Duration::from_secs(5);

/// Generate the server private key and matching client public key, both in the
/// base64url-without-padding representation used by REALITY clients.
pub fn generate_keypair() -> Result<(String, String)> {
    let mut private = [0u8; 32];
    SystemRandom::new()
        .fill(&mut private)
        .map_err(|_| anyhow!("unable to obtain random bytes for REALITY keypair"))?;
    let key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private)
        .map_err(|_| anyhow!("unable to create REALITY private key"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| anyhow!("unable to derive REALITY public key"))?;
    Ok((
        URL_SAFE_NO_PAD.encode(private),
        URL_SAFE_NO_PAD.encode(public.as_ref()),
    ))
}

#[derive(Clone)]
pub struct RealityAcceptor {
    config: Arc<Config>,
}

struct Config {
    private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    dest: String,
    hostname: String,
    max_time_diff_ms: Option<u64>,
}

pub enum Accepted {
    Reality(RealityTlsStream),
    Fallback(TcpStream, TcpStream),
}

impl RealityAcceptor {
    pub fn new(settings: RealitySettings) -> Result<Self> {
        let (hostname, port) = settings
            .dest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("REALITY destination must be hostname:port"))?;
        if hostname.is_empty()
            || port.parse::<u16>().is_err()
            || hostname.parse::<std::net::IpAddr>().is_ok()
        {
            return Err(anyhow!(
                "REALITY destination must use a DNS hostname and valid port"
            ));
        }
        let private_key = decode_key(&settings.private_key, "private")?;
        let short_ids = settings
            .short_ids
            .iter()
            .map(|id| decode_short_id(id))
            .collect::<Result<Vec<_>>>()?;
        let hostname = hostname.to_string();
        Ok(Self {
            config: Arc::new(Config {
                private_key,
                short_ids,
                dest: settings.dest,
                hostname,
                max_time_diff_ms: settings.max_time_diff_ms,
            }),
        })
    }

    pub async fn accept(&self, mut client: TcpStream) -> Result<Accepted> {
        let hello = timeout(HANDSHAKE_TIMEOUT, read_client_hello(&mut client))
            .await
            .context("REALITY ClientHello timeout")??;
        let mut target = timeout(TARGET_TIMEOUT, TcpStream::connect(&self.config.dest))
            .await
            .context("REALITY cover destination connect timeout")??;
        target.write_all(&hello).await?;
        target.flush().await?;

        // Do not consume cover-site bytes before deciding whether this is a
        // probe: an unauthenticated connection must see the destination's
        // unmodified response.
        let auth = match authenticate(&self.config, &hello) {
            Ok(auth) => auth,
            Err(_) => return Ok(Accepted::Fallback(client, target)),
        };
        let records = timeout(TARGET_TIMEOUT, read_target_flight(&mut target))
            .await
            .context("REALITY cover TLS response timeout")??;
        let stream = build_stream(&self.config, &hello, &records, auth, client)?;
        Ok(Accepted::Reality(stream))
    }
}

fn decode_key(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid REALITY {label} key"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("REALITY {label} key must decode to 32 bytes"))
}
fn decode_short_id(value: &str) -> Result<[u8; 8]> {
    if value.len() > 16 {
        return Err(anyhow!(
            "REALITY short ID must contain 0-16 hexadecimal characters"
        ));
    }
    let mut padded = value.to_owned();
    while padded.len() < 16 {
        padded.push('0');
    }
    let mut out = [0; 8];
    hex::decode_to_slice(padded, &mut out).context("invalid REALITY short ID")?;
    Ok(out)
}

fn authenticate(config: &Config, record: &[u8]) -> io::Result<[u8; 32]> {
    let hello = record.get(5..).ok_or_else(invalid)?;
    let random: [u8; 32] = hello.get(6..38).ok_or_else(invalid)?.try_into().unwrap();
    let session: [u8; 32] = hello
        .get(39..71)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    let client_key = client_x25519_key(record)?;
    let private = agreement::PrivateKey::from_private_key(&agreement::X25519, &config.private_key)
        .map_err(|_| invalid())?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, client_key);
    let mut shared = [0; 32];
    agreement::agree(&private, peer, invalid(), |secret| {
        shared.copy_from_slice(secret);
        Ok(())
    })?;
    let salt = Salt::new(HKDF_SHA256, &random[..20]);
    let prk = salt.extract(&shared);
    let okm = prk
        .expand(&[b"REALITY"], HKDF_SHA256)
        .map_err(|_| invalid())?;
    let mut auth_key = [0; 32];
    okm.fill(&mut auth_key).map_err(|_| invalid())?;
    let mut aad = hello.to_vec();
    aad[39..71].fill(0);
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).map_err(|_| invalid())?);
    let nonce = Nonce::try_assume_unique_for_key(&random[20..]).map_err(|_| invalid())?;
    let mut encrypted = session.to_vec();
    let metadata = key
        .open_in_place(nonce, Aad::from(&aad), &mut encrypted)
        .map_err(|_| denied())?;
    if metadata.len() != 16 {
        return Err(denied());
    }
    let short: [u8; 8] = metadata[8..16].try_into().unwrap();
    if !config
        .short_ids
        .iter()
        .any(|id| bool::from(id.ct_eq(&short)))
    {
        return Err(denied());
    }
    if let Some(max) = config.max_time_diff_ms {
        let stamp = u32::from_be_bytes(metadata[4..8].try_into().unwrap()) as u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        if now.abs_diff(stamp).saturating_mul(1000) > max {
            return Err(denied());
        }
    }
    Ok(auth_key)
}

fn client_x25519_key(record: &[u8]) -> io::Result<&[u8]> {
    let payload = record.get(5..).ok_or_else(invalid)?;
    if payload.len() < 43 || payload[0] != 1 {
        return Err(invalid());
    }
    let mut offset = 4 + 2 + 32;
    let sid_len = *payload.get(offset).ok_or_else(invalid)? as usize;
    offset += 1 + sid_len;
    let ciphers = u16_at(payload, offset)? as usize;
    offset += 2 + ciphers;
    let compress = *payload.get(offset).ok_or_else(invalid)? as usize;
    offset += 1 + compress;
    let ext_len = u16_at(payload, offset)? as usize;
    offset += 2;
    let end = offset
        .checked_add(ext_len)
        .filter(|end| *end == payload.len())
        .ok_or_else(invalid)?;
    while offset < end {
        let typ = u16_at(payload, offset)?;
        let len = u16_at(payload, offset + 2)? as usize;
        offset += 4;
        let data = payload.get(offset..offset + len).ok_or_else(invalid)?;
        offset += len;
        if typ != 51 {
            continue;
        }
        let mut key_offset = 2;
        let shares_len = u16_at(data, 0)? as usize;
        if shares_len + 2 != data.len() {
            return Err(invalid());
        }
        let mut hybrid = None;
        while key_offset < data.len() {
            let group = u16_at(data, key_offset)?;
            let key_len = u16_at(data, key_offset + 2)? as usize;
            key_offset += 4;
            let key = data
                .get(key_offset..key_offset + key_len)
                .ok_or_else(invalid)?;
            key_offset += key_len;
            if group == 0x001d && key.len() == 32 {
                return Ok(key);
            }
            if group == 0x11ec && key.len() == 1216 {
                hybrid = Some(&key[1184..]);
            }
        }
        return hybrid.ok_or_else(invalid);
    }
    Err(invalid())
}
fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap(),
    ))
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid REALITY ClientHello")
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "REALITY authentication failed",
    )
}

async fn read_client_hello(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let record = read_record(stream).await?;
    if record[0] != 22 || record.len() < 9 || record[5] != 1 {
        return Err(invalid());
    }
    let length =
        (usize::from(record[6]) << 16) | (usize::from(record[7]) << 8) | usize::from(record[8]);
    if length + 4 != record.len() - 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragmented REALITY ClientHello is not supported",
        ));
    }
    Ok(record)
}
async fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    stream.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if len > 16_384 + 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS record is too large",
        ));
    }
    let mut record = Vec::with_capacity(5 + len);
    record.extend_from_slice(&header);
    record.resize(5 + len, 0);
    stream.read_exact(&mut record[5..]).await?;
    Ok(record)
}
async fn read_target_flight(target: &mut TcpStream) -> io::Result<Vec<Bytes>> {
    let mut records = Vec::new();
    loop {
        let record = Bytes::from(read_record(target).await?);
        let expected = match records.len() {
            0 => 22,
            1 => 20,
            _ => 23,
        };
        if record[0] != expected || record[1..3] != [3, 3] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported REALITY cover TLS flight",
            ));
        }
        records.push(record);
        if records.len() == 3 && records[2].len() > 512 {
            return Ok(records);
        }
        if records.len() == 6 {
            return Ok(records);
        }
    }
}

fn build_stream(
    config: &Config,
    hello: &[u8],
    target: &[Bytes],
    auth: [u8; 32],
    io: TcpStream,
) -> Result<RealityTlsStream> {
    let lengths: Vec<usize> = if target.len() == 3 {
        vec![target[2].len()]
    } else if target.len() == 6 {
        target[2..6].iter().map(Bytes::len).collect()
    } else {
        return Err(anyhow!("unsupported REALITY cover TLS flight"));
    };
    if target[1].as_ref() != [20, 3, 3, 0, 1, 1] {
        return Err(anyhow!(
            "unsupported REALITY cover TLS compatibility-change record"
        ));
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let prepared =
        rustls::reality::PreparedServerHello::new(&hello[5..], &target[0][5..], &provider)
            .map_err(|e| anyhow!("unsupported REALITY cover: {e}"))?
            .with_flight_plan(
                rustls::reality::FlightPlan::new(&lengths, None)
                    .map_err(|e| anyhow!("invalid REALITY flight: {e}"))?,
            );
    let (cert, key) = certificate(&auth, &config.hostname)?;
    let certified = CertifiedKey::new(vec![cert], Arc::new(EdSigningKey(Arc::new(key))));
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let mut session = rustls::ServerConnection::new_reality(Arc::new(server_config), prepared)?;
    session.read_tls(&mut &hello[..])?;
    session.process_new_packets()?;
    let mut wire = Vec::new();
    while session.wants_write() {
        if session.write_tls(&mut wire)? == 0 {
            return Err(anyhow!("REALITY server handshake produced no output"));
        }
    }
    verify_flight(&wire, target)?;
    Ok(RealityTlsStream {
        io,
        session,
        prefix: Bytes::from(wire),
        need_flush: false,
    })
}

struct HmacKey {
    key: hmac::Key,
    public: [u8; 32],
}
impl rcgen::SigningKey for HmacKey {
    fn sign(&self, _: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        Ok(hmac::sign(&self.key, &self.public).as_ref().to_vec())
    }
}
impl rcgen::PublicKeyData for HmacKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}
fn certificate(
    auth: &[u8; 32],
    hostname: &str,
) -> Result<(CertificateDer<'static>, Ed25519KeyPair)> {
    let pair = Ed25519KeyPair::generate()
        .map_err(|_| anyhow!("unable to generate REALITY signing key"))?;
    let public: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("invalid Ed25519 public key"))?;
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names =
        vec![rcgen::SanType::DnsName(hostname.try_into().map_err(
            |_| anyhow!("invalid REALITY destination hostname"),
        )?)];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0]));
    let cert = params
        .self_signed(&HmacKey {
            key: hmac::Key::new(hmac::HMAC_SHA512, auth),
            public,
        })
        .map_err(|e| anyhow!("unable to create REALITY certificate: {e}"))?;
    Ok((cert.into(), pair))
}
struct EdSigningKey(Arc<Ed25519KeyPair>);
impl fmt::Debug for EdSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EdSigningKey")
    }
}
impl SigningKey for EdSigningKey {
    fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(Self(self.0.clone())))
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}
impl Signer for EdSigningKey {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).as_ref().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn verify_flight(wire: &[u8], target: &[Bytes]) -> Result<()> {
    let mut offset = 0;
    for (index, expected) in target.iter().enumerate() {
        let end = offset + expected.len();
        let actual = wire
            .get(offset..end)
            .ok_or_else(|| anyhow!("REALITY synthetic flight is incomplete"))?;
        if actual[..5] != expected[..5] || (index == 0 && actual[5..] != expected[5..]) {
            return Err(anyhow!(
                "REALITY synthetic flight does not match cover site"
            ));
        }
        offset = end;
    }
    if offset != wire.len() {
        return Err(anyhow!(
            "REALITY synthetic flight contains unexpected records"
        ));
    }
    Ok(())
}

pub struct RealityTlsStream {
    io: TcpStream,
    session: rustls::ServerConnection,
    prefix: Bytes,
    need_flush: bool,
}
impl RealityTlsStream {
    fn poll_drain(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while !this.prefix.is_empty() {
            let chunk = this.prefix.clone();
            let n = match Pin::new(&mut this.io).poll_write(cx, &chunk) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.prefix.advance(n);
            this.need_flush = true;
        }
        while this.session.wants_write() {
            let RealityTlsStream {
                io: socket,
                session,
                ..
            } = this;
            let mut writer = PollWriter { io: socket, cx };
            match session.write_tls(&mut writer) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => this.need_flush = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
    fn poll_receive(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let RealityTlsStream {
            io: socket,
            session,
            ..
        } = this;
        let mut reader = PollReader { io: socket, cx };
        match session.read_tls(&mut reader) {
            Ok(0) => return Poll::Ready(Ok(())),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };
        session
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.session.reader().fill_buf() {
                Ok(data) if !data.is_empty() => {
                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    self.session.reader().consume(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            match self.as_mut().poll_drain(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
            match self.as_mut().poll_receive(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.as_mut().poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let n = self.session.writer().write(data)?;
        match self.as_mut().poll_drain(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Pending if n > 0 => Poll::Ready(Ok(n)),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_drain(cx))?;
        if self.need_flush {
            match Pin::new(&mut self.io).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.need_flush = false,
                other => return other,
            }
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.session.send_close_notify();
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
struct PollReader<'a, 'b> {
    io: &'a mut TcpStream,
    cx: &'a mut TaskContext<'b>,
}
impl Read for PollReader<'_, '_> {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(data);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
struct PollWriter<'a, 'b> {
    io: &'a mut TcpStream,
    cx: &'a mut TaskContext<'b>,
}
impl Write for PollWriter<'_, '_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, data) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_key, generate_keypair};
    use aws_lc_rs::agreement;
    use base64::Engine as _;

    #[test]
    fn generated_keypair_has_matching_x25519_public_key() {
        let (private, public) = generate_keypair().unwrap();
        let private = decode_key(&private, "private").unwrap();
        let expected = agreement::PrivateKey::from_private_key(&agreement::X25519, &private)
            .unwrap()
            .compute_public_key()
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected.as_ref()),
            public
        );
    }
}
