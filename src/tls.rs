use std::sync::Arc;
use tokio_rustls::{TlsAcceptor};
use rustls::{ServerConfig};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use anyhow::{anyhow, Result};

use crate::TransportMode;
use crate::logger::log;

pub fn get_tls_acceptor(cert_path: Option<String>, key_path: Option<String>, transport_mode: TransportMode) -> Option<TlsAcceptor> {
    match (cert_path, key_path) {
        (Some(cert_path_str), Some(key_path_str)) => {
            log::info!(cert = %cert_path_str, key = %key_path_str, "Loading TLS certificates");
            Some(load_tls_config_with_transport_mode(&cert_path_str, &key_path_str, transport_mode).unwrap())
        }
        _ => {
            return None;
        }
    }
}

fn load_tls_config_with_transport_mode(cert_path: &str, key_path: &str, transport_mode: TransportMode) -> Result<TlsAcceptor> {
    let mut config = load_tls_config(cert_path, key_path)?;
    config.alpn_protocols = match transport_mode {
        TransportMode::Grpc => {
            vec![b"h2".to_vec()]
        }
        _ => {
            vec![b"http/1.1".to_vec()]
        }
    };
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
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
    
    Ok(config)
}
