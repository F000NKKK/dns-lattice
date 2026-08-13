//! DNS-over-TLS upstream backend (RFC 7858), behind the `dot` Cargo
//! feature. Per ADR-0012 (`DL-A-13`): TLS via `rustls`/`tokio-rustls`
//! (pure-Rust, no platform-native TLS dependency), reusing the same
//! RFC 1035 §4.2.2 2-byte length-prefixed framing as [`super::TcpBackend`]
//! once the TLS handshake completes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::Message;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;

use super::{UpstreamBackend, framed_query};

/// Configuration for [`DotBackend`].
#[derive(Clone)]
pub struct DotBackendConfig {
    /// The upstream DoT server's socket address, conventionally port 853
    /// (RFC 7858 §3.1).
    pub server: SocketAddr,
    /// The server name used both for TLS SNI and certificate hostname
    /// verification.
    pub server_name: ServerName<'static>,
    /// The `rustls` client configuration (root trust store, ALPN
    /// protocols, etc.) used to establish the TLS session. Use
    /// [`DotBackendConfig::with_webpki_roots`] for the common case of
    /// verifying against the Mozilla root program via `webpki-roots`.
    pub tls_config: Arc<ClientConfig>,
    /// Bounds the TCP connect phase.
    pub connect_timeout: Duration,
    /// Bounds the TLS handshake and each subsequent write/read on the
    /// established session.
    pub read_timeout: Duration,
}

impl DotBackendConfig {
    /// Builds a config that verifies the server's certificate against the
    /// Mozilla root program (`webpki-roots`), with no client certificate
    /// and TLS 1.2/1.3 support. This is the common case for a public DoT
    /// resolver; a caller with a private CA or pinned certificate should
    /// build `tls_config` directly instead.
    pub fn with_webpki_roots(
        server: SocketAddr,
        server_name: ServerName<'static>,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Self {
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            server,
            server_name,
            tls_config: Arc::new(tls_config),
            connect_timeout,
            read_timeout,
        }
    }
}

/// DNS-over-TLS upstream backend (RFC 7858), gated behind the `dot` Cargo
/// feature. Follows the same `Config` + `Backend` +
/// `#[async_trait] impl UpstreamBackend` pattern as [`super::UdpBackend`]/
/// [`super::TcpBackend`] (ADR-0011); this backend adds no fields or
/// methods to the [`UpstreamBackend`] trait itself.
///
/// An underlying TCP failure before a TLS session is established (including
/// a peer closing the connection) maps to [`Error::Transport`], matching
/// [`super::TcpBackend`]'s own connection-failure mapping. A failure that
/// `rustls` reports during TLS negotiation or certificate/hostname
/// verification maps to [`Error::Tls`] (ADR-0012).
pub struct DotBackend {
    config: DotBackendConfig,
}

impl DotBackend {
    /// Builds a DoT backend from `config`.
    pub fn new(config: DotBackendConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UpstreamBackend for DotBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let stream = timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.config.server),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;

        let connector = TlsConnector::from(self.config.tls_config.clone());
        let mut tls_stream = timeout(
            self.config.read_timeout,
            connector.connect(self.config.server_name.clone(), stream),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(map_tls_connect_error)?;

        framed_query(&mut tls_stream, self.config.read_timeout, query).await
    }
}

/// Maps a failed TLS setup to [`Error::Tls`] only when `rustls` actually
/// reported a TLS error. A peer that resets or closes the underlying TCP
/// connection before a TLS session exists is a transport failure instead.
fn map_tls_connect_error(err: std::io::Error) -> Error {
    if error_chain_is_tls(&err) {
        Error::Tls(err.to_string())
    } else {
        Error::Transport(err.to_string())
    }
}

fn error_chain_is_tls(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if node.downcast_ref::<tokio_rustls::rustls::Error>().is_some() {
            return true;
        }
        if let Some(io_err) = node.downcast_ref::<std::io::Error>()
            && let Some(inner) = io_err.get_ref()
            && error_chain_is_tls(inner)
        {
            return true;
        }
        current = node.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{Class, Header, Name, Opcode, Question, Rcode, RecordType};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::{RootCertStore, ServerConfig};

    fn query_for(name: &str) -> Message {
        Message {
            header: Header {
                id: 11,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: Name::from_ascii(name).unwrap(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn answer_for(name: &str, id: u16) -> Message {
        let mut msg = query_for(name);
        msg.header.id = id;
        msg.header.qr = true;
        msg
    }

    /// Generates a self-signed loopback certificate (`localhost`/127.0.0.1)
    /// plus a matching `rustls` server config, and a client `ClientConfig`
    /// that trusts exactly that certificate (not the system/webpki root
    /// store) — fully offline and deterministic per `@.claude/rules/ci.md`.
    fn self_signed_fixture() -> (ServerConfig, ClientConfig, ServerName<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let server_name = ServerName::try_from("localhost").unwrap();
        (server_config, client_config, server_name)
    }

    #[tokio::test]
    async fn dot_backend_resolves_against_a_loopback_tls_server() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();

            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            tls_stream.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();

            let response = answer_for("example.com", query.header.id);
            let bytes = response.encode().unwrap();
            let framed_len: u16 = bytes.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&framed_len.to_be_bytes());
            framed.extend_from_slice(&bytes);
            tls_stream.write_all(&framed).await.unwrap();
        });

        let backend = DotBackend::new(DotBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("dot backend resolves");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn dot_backend_returns_tls_error_on_untrusted_certificate() {
        // The server presents a self-signed cert the client does NOT
        // trust (a second, independent self-signed fixture), so the TLS
        // handshake itself must fail with `Error::Tls`, not `Transport`.
        let (server_config, _matching_client_config, _server_name) = self_signed_fixture();
        let (_other_server_config, untrusting_client_config, server_name) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            // The handshake is expected to fail client-side before any
            // application data is exchanged; a handshake error on the
            // accept side is an acceptable outcome here too.
            let _ = acceptor.accept(tcp_stream).await;
        });

        let backend = DotBackend::new(DotBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(untrusting_client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("untrusted certificate fails the tls handshake");
        assert!(matches!(err, Error::Tls(_)));
        let _ = responder.await;
    }

    #[tokio::test]
    async fn dot_backend_returns_transport_when_peer_closes_before_tls() {
        let (_server_config, client_config, server_name) = self_signed_fixture();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let backend = DotBackend::new(DotBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer that closes before TLS is a transport failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn dot_backend_times_out_when_server_never_completes_handshake() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let _acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept the TCP connection but never drive the TLS handshake, so
        // the client-side handshake never completes within the budget.
        // Blocks on a `oneshot` receiver that is never sent to (never a
        // real timer sleep, per `@.claude/rules/ci.md`) until the test
        // aborts this task after asserting the client-side timeout fired.
        let (_never_sent, wait_forever) = tokio::sync::oneshot::channel::<()>();
        let responder = tokio::spawn(async move {
            let (_tcp_stream, _) = listener.accept().await.unwrap();
            let _ = wait_forever.await;
        });

        let backend = DotBackend::new(DotBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_millis(50),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("handshake does not complete within the timeout budget");
        assert_eq!(err, Error::Timeout);
        responder.abort();
    }
}
