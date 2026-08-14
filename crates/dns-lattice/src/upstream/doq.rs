//! DNS-over-QUIC upstream backend (RFC 9250), behind the `doq` Cargo
//! feature. QUIC transport uses `quinn`, with TLS 1.3
//! (embedded in QUIC itself) via `rustls`, one fresh `quinn::Endpoint` +
//! `quinn::Connection` per query (no connection pooling/reuse this stage),
//! reusing [`super::framed_query`]'s RFC 1035 §4.2.2 2-byte length-prefixed
//! DNS message framing on a single bidirectional QUIC stream, and no 0-RTT
//! for queries (replay-safety, RFC 9250 §4.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::Message;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, ConnectionError, Endpoint, RecvStream, SendStream};
use rustls::ClientConfig as RustlsClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;

use super::{UpstreamBackend, framed_query};

/// The ALPN protocol identifier for DNS-over-QUIC (RFC 9250 §4.1.1).
const DOQ_ALPN: &[u8] = b"doq";

/// Configuration for [`DoqBackend`].
#[derive(Clone)]
pub struct DoqBackendConfig {
    /// The upstream DoQ server's socket address, conventionally port 853
    /// (RFC 9250 §4, disambiguated from DoT by ALPN rather than port).
    pub server: SocketAddr,
    /// The server name used both for QUIC/TLS SNI and certificate hostname
    /// verification.
    pub server_name: ServerName<'static>,
    /// The `rustls` client configuration used to establish the QUIC
    /// connection's embedded TLS 1.3 session. Its `alpn_protocols` MUST
    /// include `doq` (RFC 9250 §4.1.1) —
    /// [`DoqBackendConfig::with_webpki_roots`] sets this correctly for the
    /// common case; a caller building `tls_config` directly is responsible
    /// for setting it, as with any caller-built encrypted-transport
    /// `ClientConfig`.
    pub tls_config: Arc<RustlsClientConfig>,
    /// Bounds establishing the QUIC connection (UDP handshake through TLS
    /// 1.3 completion).
    pub connect_timeout: Duration,
    /// Bounds each query's open-stream/write/read round trip on an
    /// established connection.
    pub read_timeout: Duration,
}

impl DoqBackendConfig {
    /// Builds a config that verifies the server's certificate against the
    /// Mozilla root program (`webpki-roots`), with no client certificate,
    /// TLS 1.3 only (QUIC requires TLS 1.3, RFC 9000 §7), and ALPN set to
    /// `doq`. This is the common case for a public DoQ resolver; a caller
    /// with a private CA or pinned certificate should build `tls_config`
    /// directly instead.
    pub fn with_webpki_roots(
        server: SocketAddr,
        server_name: ServerName<'static>,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = RustlsClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        Self {
            server,
            server_name,
            tls_config: Arc::new(tls_config),
            connect_timeout,
            read_timeout,
        }
    }
}

/// DNS-over-QUIC upstream backend (RFC 9250), gated behind the `doq` Cargo
/// feature. Follows the same `Config` + `Backend` +
/// `#[async_trait] impl UpstreamBackend` pattern as the other transport
/// backends; this backend
/// adds no fields or methods to the [`UpstreamBackend`] trait itself.
///
/// Opens a fresh `quinn::Endpoint` and `quinn::Connection` per
/// [`UpstreamBackend::resolve`] call — no connection pooling/reuse this
/// stage, matching the per-call connection lifetime of the other encrypted
/// backends. A pre-handshake QUIC/UDP-layer failure
/// (endpoint bind, `Endpoint::connect`, or a post-handshake QUIC transport/
/// stream failure) maps to [`Error::Transport`]; a failure attributable to
/// the QUIC connection's embedded TLS 1.3 handshake maps to [`Error::Tls`].
pub struct DoqBackend {
    config: DoqBackendConfig,
}

impl DoqBackend {
    /// Builds a DoQ backend from `config`.
    pub fn new(config: DoqBackendConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UpstreamBackend for DoqBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let quic_client_config: QuicClientConfig =
            self.config.tls_config.clone().try_into().map_err(
                |err: quinn::crypto::rustls::NoInitialCipherSuite| Error::Tls(err.to_string()),
            )?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        let bind_addr = unspecified_like(self.config.server);
        let endpoint = Endpoint::client(bind_addr)
            .map_err(|err| Error::Transport(format!("binding QUIC endpoint: {err}")))?;

        let server_name = self.config.server_name.to_str();
        let connecting = endpoint
            .connect_with(client_config, self.config.server, server_name.as_ref())
            .map_err(|err| Error::Transport(err.to_string()))?;

        let connection = timeout(self.config.connect_timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(connection_error_to_lattice_error)?;

        let (send, recv) = timeout(self.config.connect_timeout, connection.open_bi())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(connection_error_to_lattice_error)?;

        let mut stream = QuicStream { send, recv };
        let response = framed_query(&mut stream, self.config.read_timeout, query).await;

        // Per RFC 9250 §4.2, the client SHOULD close the send side of the
        // stream gracefully after sending the query. Attempted for both
        // the success and failure path (best-effort; a failure to finish
        // an already-broken stream is not itself surfaced as an error).
        let _ = stream.send.finish();

        response
    }
}

/// Combines a `quinn` bidirectional stream's independent send/receive
/// halves into a single type implementing `tokio::io::{AsyncRead,
/// AsyncWrite} + Unpin`, satisfying [`framed_query`]'s generic bound
/// without any change to `framed_query` itself.
///
/// `pub(crate)` (not private) so `crate::server`'s DoQ listener
/// can reuse this exact adapter for its
/// per-stream `read_framed`/`write_framed` calls instead of reimplementing
/// it — same sharing precedent as [`super::read_framed`]/
/// [`super::write_framed`] themselves.
pub(crate) struct QuicStream {
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Returns the unspecified address (`0.0.0.0`/`::`) matching `addr`'s
/// address family, on port `0` (OS-assigned ephemeral port), for binding
/// the local client-side QUIC `Endpoint`.
fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

/// Classifies a post-`connect_with` [`ConnectionError`] onto the
/// `Error::Tls`/`Error::Transport` boundary.
///
/// `quinn`/`quinn-proto` do not expose a dedicated "this failure was the
/// embedded TLS handshake" variant on [`ConnectionError`] — a certificate/
/// ALPN/handshake failure surfaces as `ConnectionError::TransportError`
/// carrying a QUIC CRYPTO_ERROR code (RFC 9000 §20.1's `0x0100..=0x01ff`
/// range, populated from the TLS alert). `quinn-proto`'s own `Display`
/// impl for that error code renders exactly the substring "the
/// cryptographic handshake failed" for that range and nothing else in its
/// error catalog — checked here as a pragmatic, versioned classification
/// (documented as such, not treated as a stable public contract of
/// `quinn`) rather than reaching into `quinn-proto`'s private `Code` inner
/// value, which has no public accessor. All other `ConnectionError`
/// variants (`VersionMismatch`, `ConnectionClosed`, `ApplicationClosed`,
/// `Reset`, `TimedOut`, `LocallyClosed`, `CidsExhausted`, and any
/// `TransportError` whose code is not in the crypto range) map to
/// `Error::Transport`.
fn connection_error_to_lattice_error(err: ConnectionError) -> Error {
    let message = err.to_string();
    if matches!(err, ConnectionError::TransportError(_))
        && message.contains("cryptographic handshake failed")
    {
        Error::Tls(message)
    } else {
        Error::Transport(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{Class, Header, Name, Opcode, Question, Rcode, RecordType};
    use quinn::crypto::rustls::QuicServerConfig;
    use quinn::{ServerConfig, TransportConfig};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};

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

    /// Generates a self-signed loopback certificate (`localhost`) plus a
    /// matching `quinn`/`rustls` server config (ALPN `doq`), and a client
    /// `rustls::ClientConfig` (ALPN `doq`) that trusts exactly that
    /// certificate (not the system/webpki root store) — fully offline and
    /// deterministic per `@.claude/rules/ci.md`, mirroring `dot.rs`'s
    /// `self_signed_fixture`.
    fn self_signed_fixture() -> (ServerConfig, RustlsClientConfig, ServerName<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();

        let mut rustls_server_config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        rustls_server_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let quic_server_config: QuicServerConfig = rustls_server_config
            .try_into()
            .expect("valid TLS 1.3 initial cipher suite");
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        // Keep the idle timeout short so a test server that is never
        // driven to completion (the timeout test below) does not keep a
        // background task alive past the test itself.
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(5).try_into().unwrap()));
        server_config.transport_config(Arc::new(transport));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_config = RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let server_name = ServerName::try_from("localhost").unwrap();
        (server_config, client_config, server_name)
    }

    #[tokio::test]
    async fn doq_backend_resolves_against_a_loopback_quic_server() {
        let (server_config, client_config, server_name) = self_signed_fixture();

        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();

            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            recv.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();

            let response = answer_for("example.com", query.header.id);
            let bytes = response.encode().unwrap();
            let framed_len: u16 = bytes.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&framed_len.to_be_bytes());
            framed.extend_from_slice(&bytes);
            send.write_all(&framed).await.unwrap();
            let _ = send.finish();
            // Wait for the peer to acknowledge/stop the stream before this
            // task (and therefore `connection`/`endpoint`) drops — dropping
            // a `quinn::Connection` immediately closes it at the
            // application layer (`ApplicationClose` code 0), which can
            // race ahead of the client's still-in-flight read of the
            // response that was just written. This is a test-fixture
            // concern only: a long-lived production server naturally
            // keeps its connections/endpoint alive across many queries.
            let _ = send.stopped().await;
        });

        let backend = DoqBackend::new(DoqBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("doq backend resolves");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doq_backend_returns_tls_error_on_untrusted_certificate() {
        // The server presents a self-signed cert the client does NOT
        // trust (a second, independent self-signed fixture), so the QUIC
        // connection's embedded TLS handshake must fail with
        // `Error::Tls`, not `Transport`.
        let (server_config, _matching_client_config, _server_name) = self_signed_fixture();
        let (_other_server_config, untrusting_client_config, server_name) = self_signed_fixture();

        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            // The handshake is expected to fail client-side before any
            // application data is exchanged; a handshake error on the
            // accept side is an acceptable outcome here too.
            if let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });

        let backend = DoqBackend::new(DoqBackendConfig {
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
        assert!(
            matches!(err, Error::Tls(_)),
            "expected Error::Tls, got {err:?}"
        );
        responder.abort();
    }

    #[tokio::test]
    async fn doq_backend_transport_error_on_connect_failure() {
        let (_server_config, client_config, server_name) = self_signed_fixture();

        // Bind then immediately drop a UDP-backed endpoint so the port is
        // very likely to have nothing listening; a `quinn` client
        // connecting to an address with no QUIC endpoint waits for the
        // handshake to time out at the QUIC layer rather than an
        // immediate ICMP-style refusal (QUIC handshakes are UDP-based and
        // have no direct "connection refused" signal), so this deliberately
        // exercises the `connect_timeout` budget expiring while the
        // handshake is unable to make any progress -- distinct from the
        // TLS-handshake-failure case above (no peer ever responds here,
        // vs. a peer that responds and is then rejected on trust grounds).
        let placeholder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = placeholder.local_addr().unwrap();
        drop(placeholder);

        let backend = DoqBackend::new(DoqBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("connecting to a QUIC endpoint with no listener times out");
        assert_eq!(err, Error::Timeout);
    }

    #[tokio::test]
    async fn doq_backend_times_out_when_server_never_completes_handshake() {
        let (server_config, client_config, server_name) = self_signed_fixture();

        // Bind a real QUIC-capable UDP socket but never accept/drive any
        // connection on it, so the client-side handshake never completes
        // within the budget. This deterministically exercises
        // `connect_timeout` without a real `sleep`, per
        // `@.claude/rules/ci.md`.
        let _server_config = server_config;
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Keep the socket bound (not accepting QUIC) for the test's
        // duration so the port stays claimed without answering.
        let _keep_alive = listener;

        let backend = DoqBackend::new(DoqBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_millis(50),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("handshake does not complete within the timeout budget");
        assert_eq!(err, Error::Timeout);
    }
}
