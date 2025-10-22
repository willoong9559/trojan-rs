use std::sync::Arc;
use tokio_rustls::{TlsAcceptor};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use anyhow::{anyhow, Result};

pub fn get_tls_acceptor(cert_path: Option<String>, key_path: Option<String>) -> Option<TlsAcceptor> {
    match (cert_path, key_path) {
        (Some(cert_path_str), Some(key_path_str)) => {
            println!("Loading TLS certificates from: {}, {}", cert_path_str, key_path_str);
            Some(load_tls_config(&cert_path_str, &key_path_str).unwrap())
        }
        (None, None) => {
            None
        }
        _ => {
            None
        }
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("No certificates found in {}", cert_path));
    }

    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)?;

    let key = key.ok_or_else(|| anyhow!("No private key found in {}", key_path))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}