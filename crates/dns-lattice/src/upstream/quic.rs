//! QUIC client plumbing shared by the QUIC-based upstream backends.
//!
//! A backend that reuses connections owns one [`QuicClient`]: it keeps a
//! single `quinn::Endpoint` (one UDP socket and one driver task) for the
//! backend's whole life and opens every pooled connection on it, instead of
//! binding a socket per query. The endpoint is created lazily inside the
//! runtime that first connects, because `quinn` needs a runtime to start its
//! driver and a backend may be built outside one. When a later connect runs on
//! a different runtime (the first one was shut down and took the endpoint's
//! driver with it), the endpoint is replaced.
//!
//! The module is deliberately independent of DNS framing so a second QUIC
//! transport can use it unchanged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dns_lattice_core::{Error, Result};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, ConnectionError, Endpoint, IdleTimeout, TransportConfig};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::runtime::{Handle, Id as RuntimeId};
use tokio::time::timeout;

/// The application error code of a graceful close (RFC 9250 §4.3, DOQ_NO_ERROR
/// and, for HTTP/3, H3_NO_ERROR).
pub(crate) const NO_ERROR: u32 = 0;

/// How much longer than a pool's idle timeout the QUIC transport waits before
/// it closes a silent connection itself, so the pool's graceful close wins the
/// race and is counted as an idle close.
pub(crate) const TRANSPORT_IDLE_MARGIN: Duration = Duration::from_secs(2);

/// Builds the `quinn` client configuration for `tls_config`, optionally with a
/// QUIC idle timeout. Without one the `quinn` default applies.
pub(crate) fn client_config(
    tls_config: &Arc<RustlsClientConfig>,
    idle_timeout: Option<Duration>,
) -> Result<ClientConfig> {
    let quic: QuicClientConfig = Arc::clone(tls_config)
        .try_into()
        .map_err(|err: quinn::crypto::rustls::NoInitialCipherSuite| Error::Tls(err.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(quic));
    if let Some(idle) = idle_timeout.and_then(|d| IdleTimeout::try_from(d).ok()) {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(idle));
        config.transport_config(Arc::new(transport));
    }
    Ok(config)
}

/// Returns the unspecified address (`0.0.0.0`/`::`) matching `addr`'s address
/// family, on port `0` (OS-assigned ephemeral port), for binding the local
/// client-side QUIC endpoint.
pub(crate) fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Classifies a [`ConnectionError`] onto the `Error::Tls`/`Error::Transport`
/// boundary.
///
/// `quinn`/`quinn-proto` do not expose a dedicated "this failure was the
/// embedded TLS handshake" variant on [`ConnectionError`]: a certificate,
/// ALPN or handshake failure surfaces as `ConnectionError::TransportError`
/// carrying a QUIC CRYPTO_ERROR code (RFC 9000 §20.1's `0x0100..=0x01ff`
/// range, populated from the TLS alert). `quinn-proto`'s own `Display` impl
/// for that error code renders exactly the substring "the cryptographic
/// handshake failed" for that range and nothing else in its error catalog, so
/// it is checked here as a pragmatic, versioned classification (not a stable
/// public contract of `quinn`). Every other variant maps to
/// `Error::Transport`.
pub(crate) fn connection_error_to_lattice_error(err: ConnectionError) -> Error {
    let message = err.to_string();
    if matches!(err, ConnectionError::TransportError(_))
        && message.contains("cryptographic handshake failed")
    {
        Error::Tls(message)
    } else {
        Error::Transport(message)
    }
}

/// The endpoint together with the runtime whose driver task serves it.
struct Bound {
    runtime: RuntimeId,
    endpoint: Endpoint,
}

/// Opens QUIC connections to one server through one shared endpoint.
pub(crate) struct QuicClient {
    server: SocketAddr,
    server_name: String,
    config: Result<ClientConfig>,
    connect_timeout: Duration,
    bound: Mutex<Option<Bound>>,
}

impl QuicClient {
    /// Describes the server. No socket is bound and no task started until the
    /// first [`QuicClient::connect`]. A TLS configuration `quinn` cannot use
    /// is reported by that first connect.
    pub(crate) fn new(
        server: SocketAddr,
        server_name: &str,
        tls_config: &Arc<RustlsClientConfig>,
        idle_timeout: Option<Duration>,
        connect_timeout: Duration,
    ) -> Self {
        QuicClient {
            server,
            server_name: server_name.to_owned(),
            config: client_config(tls_config, idle_timeout),
            connect_timeout,
            bound: Mutex::new(None),
        }
    }

    /// The shared endpoint, bound on first use and rebound when the runtime
    /// that served it is gone.
    fn endpoint(&self) -> Result<Endpoint> {
        let runtime = Handle::try_current()
            .map_err(|err| Error::Transport(format!("no Tokio runtime: {err}")))?
            .id();
        let mut bound = self.bound.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(current) = bound.as_ref()
            && current.runtime == runtime
        {
            return Ok(current.endpoint.clone());
        }
        let endpoint = Endpoint::client(unspecified_like(self.server))
            .map_err(|err| Error::Transport(format!("binding QUIC endpoint: {err}")))?;
        if let Some(old) = bound.replace(Bound {
            runtime,
            endpoint: endpoint.clone(),
        }) {
            // Its driver died with its runtime; this only releases the socket.
            old.endpoint.close(quinn::VarInt::from_u32(NO_ERROR), &[]);
        }
        Ok(endpoint)
    }

    /// Opens a connection (UDP handshake through TLS 1.3 completion), bounded
    /// by the connect timeout. No 0-RTT: the connection is only used once the
    /// handshake has completed.
    pub(crate) async fn connect(&self) -> Result<Connection> {
        let config = self.config.clone()?;
        let endpoint = self.endpoint()?;
        let connecting = endpoint
            .connect_with(config, self.server, &self.server_name)
            .map_err(|err| Error::Transport(err.to_string()))?;
        timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(connection_error_to_lattice_error)
    }

    /// The runtime the calling task runs on.
    pub(crate) fn current_runtime() -> Option<RuntimeId> {
        Handle::try_current().ok().map(|handle| handle.id())
    }
}
