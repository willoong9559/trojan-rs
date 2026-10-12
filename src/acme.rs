use anyhow::{Context, Result};
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls_acme::{caches::DirCache, AcmeAcceptor, AcmeConfig};

use crate::config::AcmeSettings;
use crate::logger::log;
use crate::TransportMode;

const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

#[derive(Clone)]
pub struct AcmeTls {
    acceptor: AcmeAcceptor,
    tls_config: Arc<rustls::ServerConfig>,
}

impl AcmeTls {
    pub fn new(settings: &AcmeSettings, transport_mode: TransportMode) -> Result<Self> {
        prepare_cache_dir(&settings.cache_dir)?;

        let mut state = AcmeConfig::new([settings.domain.as_str()])
            .contact_push(format!("mailto:{}", settings.email))
            .cache(DirCache::new(std::path::PathBuf::from(&settings.cache_dir)))
            .directory_lets_encrypt(!settings.staging)
            .state();
        let acceptor = state.acceptor();
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver());
        tls_config.alpn_protocols = match transport_mode {
            TransportMode::Grpc | TransportMode::Tcp => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            TransportMode::WebSocket => vec![b"http/1.1".to_vec()],
        };

        tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(event) => log::info!(event = ?event, "ACME certificate event"),
                    Err(error) => log::error!(error = ?error, "ACME certificate event failed"),
                }
            }
        });

        Ok(Self {
            acceptor,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Returns `None` after handling a TLS-ALPN-01 validation connection.
    pub async fn accept<S>(&self, stream: S) -> Result<Option<TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start_handshake = tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
            self.acceptor.accept(stream),
        )
        .await
        .context("TLS ClientHello timeout")??;

        let Some(start_handshake) = start_handshake else {
            return Ok(None);
        };

        let stream = tokio::time::timeout(
            Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
            start_handshake.into_stream(Arc::clone(&self.tls_config)),
        )
        .await
        .context("TLS handshake timeout")??;
        Ok(Some(stream))
    }
}

fn prepare_cache_dir(path: &str) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
