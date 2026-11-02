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

/// A process-wide ACME account and certificate resolver shared by opted-in
/// inbounds. Each inbound obtains its own ALPN-specific TLS configuration.
#[derive(Clone)]
pub struct AcmeManager {
    acceptor: AcmeAcceptor,
    resolver: Arc<tokio_rustls_acme::ResolvesServerCertAcme>,
}

impl AcmeManager {
    pub fn new(settings: &AcmeSettings) -> Result<Self> {
        prepare_cache_dir(&settings.cache_dir)?;

        let mut state = AcmeConfig::new([settings.domain.as_str()])
            .contact_push(format!("mailto:{}", settings.email))
            .cache(DirCache::new(std::path::PathBuf::from(&settings.cache_dir)))
            .directory_lets_encrypt(!settings.staging)
            .state();
        let acceptor = state.acceptor();
        let resolver = state.resolver();

        tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(event) => log::info!(event = ?event, "ACME certificate event"),
                    Err(error) => log::error!(error = ?error, "ACME certificate event failed"),
                }
            }
        });

        Ok(Self { acceptor, resolver })
    }

    pub fn tls_for_transport(&self, transport_mode: TransportMode) -> AcmeTls {
        let resolver: Arc<dyn rustls::server::ResolvesServerCert> = self.resolver.clone();
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        tls_config.alpn_protocols = match transport_mode {
            TransportMode::Grpc | TransportMode::Tcp => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            TransportMode::WebSocket => vec![b"http/1.1".to_vec()],
        };
        AcmeTls {
            acceptor: self.acceptor.clone(),
            tls_config: Arc::new(tls_config),
        }
    }
}

/// TLS handling for one ACME-enabled inbound.
#[derive(Clone)]
pub struct AcmeTls {
    acceptor: AcmeAcceptor,
    tls_config: Arc<rustls::ServerConfig>,
}

impl AcmeTls {
    /// `None` means this connection was consumed by TLS-ALPN-01 validation.
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
