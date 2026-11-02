use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::ServerConfig;
use std::fs;
use std::io::{BufReader, Cursor};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::logger::log;
use crate::TransportMode;

pub fn get_tls_acceptor(
    cert_path: Option<String>,
    key_path: Option<String>,
    cert_chain_paths: Vec<String>,
    transport_mode: TransportMode,
) -> Result<Option<TlsAcceptor>> {
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            log::info!(cert = %cert_path, key = %key_path, "Loading TLS certificates");
            Ok(Some(load_tls_config_with_transport_mode(
                &cert_path,
                &key_path,
                &cert_chain_paths,
                transport_mode,
            )?))
        }
        (None, None) => Ok(None),
        _ => Err(anyhow!("TLS requires both cert and key")),
    }
}

fn load_tls_config_with_transport_mode(
    cert_path: &str,
    key_path: &str,
    cert_chain_paths: &[String],
    transport_mode: TransportMode,
) -> Result<TlsAcceptor> {
    let mut config = load_tls_config(cert_path, key_path, cert_chain_paths)?;
    config.alpn_protocols = match transport_mode {
        TransportMode::Grpc | TransportMode::Tcp => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        TransportMode::WebSocket => vec![b"http/1.1".to_vec()],
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    cert_chain_paths: &[String],
) -> Result<ServerConfig> {
    let mut certs = load_certificates(cert_path)?;
    for chain_path in cert_chain_paths {
        certs.extend(load_certificates(chain_path)?);
    }

    let key_bytes =
        fs::read(key_path).with_context(|| format!("failed to read TLS private key {key_path}"))?;
    if is_pem(&key_bytes) {
        let mut reader = BufReader::new(Cursor::new(key_bytes));
        let key = rustls_pemfile::private_key(&mut reader)
            .with_context(|| format!("failed to parse PEM private key {key_path}"))?
            .ok_or_else(|| anyhow!("no private key found in {key_path}"))?;
        return server_config_with_key(certs, key);
    }

    server_config_with_der_key(certs, key_bytes, key_path)
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read TLS certificate {path}"))?;
    if is_pem(&bytes) {
        let mut reader = BufReader::new(Cursor::new(bytes));
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse PEM certificate {path}"))?;
        if certs.is_empty() {
            return Err(anyhow!("no certificates found in {path}"));
        }
        Ok(certs)
    } else if bytes.is_empty() {
        Err(anyhow!("certificate file {path} is empty"))
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

fn server_config_with_der_key(
    certs: Vec<CertificateDer<'static>>,
    key_bytes: Vec<u8>,
    key_path: &str,
) -> Result<ServerConfig> {
    let candidates = [
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes.clone())),
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key_bytes.clone())),
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key_bytes)),
    ];
    let mut errors = Vec::new();
    for key in candidates {
        match server_config_with_key(certs.clone(), key) {
            Ok(config) => return Ok(config),
            Err(error) => errors.push(error.to_string()),
        }
    }

    Err(anyhow!(
        "failed to parse DER private key {key_path} as PKCS#8, PKCS#1, or SEC1: {}",
        errors.join("; ")
    ))
}

fn server_config_with_key(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(Into::into)
}

fn is_pem(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take(b"-----BEGIN".len())
        .eq(b"-----BEGIN".iter())
}

#[cfg(test)]
mod tests {
    use super::{get_tls_acceptor, is_pem, server_config_with_der_key};
    use crate::TransportMode;

    #[test]
    fn detects_pem_after_leading_whitespace() {
        assert!(is_pem(b"\n  -----BEGIN CERTIFICATE-----\n"));
        assert!(!is_pem(&[0x30, 0x82, 0x01, 0x00]));
    }

    #[test]
    fn accepts_der_certificate_and_pkcs8_private_key() {
        // The binary installs AWS-LC before constructing any TLS config. Unit
        // tests call this helper directly, so reproduce that process setup.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();

        server_config_with_der_key(
            vec![certificate.der().clone()],
            key.serialize_der(),
            "test-key.der",
        )
        .unwrap();
    }

    #[test]
    fn tls_requires_certificate_and_key_together() {
        assert!(get_tls_acceptor(
            Some("certificate.pem".to_string()),
            None,
            Vec::new(),
            TransportMode::Tcp,
        )
        .is_err());
    }
}
