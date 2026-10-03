//! DNS-over-TLS upstream backend (RFC 7858), behind the `dot` Cargo
//! feature. TLS uses `rustls`/`tokio-rustls`
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
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;

use super::{
    IdCheck, PoolConfig, PoolStats, StreamOpen, StreamPool, UpstreamBackend, framed_query,
};

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
/// [`super::TcpBackend`]; this backend adds no fields or
/// methods to the [`UpstreamBackend`] trait itself.
///
/// An underlying TCP failure before a TLS session is established (including
/// a peer closing the connection) maps to [`Error::Transport`], matching
/// [`super::TcpBackend`]'s own connection-failure mapping. A failure that
/// `rustls` reports during TLS negotiation or certificate/hostname
/// verification maps to [`Error::Tls`].
///
/// # Connection reuse
///
/// By default the backend keeps a small pool of TLS connections to the
/// upstream and pipelines the queries of all callers over them (RFC 7858
/// §3.3), so a query does not pay a TCP and TLS handshake. Answers may arrive
/// in any order; every caller gets the answer to its own question with its
/// own message id. A [`PoolConfig`] passed to [`with_pool`](Self::with_pool)
/// sets the bounds (connections, queries per connection, idle timeout,
/// maximum lifetime), [`pool_stats`](Self::pool_stats) reports what the pool
/// did, and [`PoolConfig::disabled`] restores one connection per query.
///
/// The handshake of every new connection verifies the server certificate
/// against `server_name` again, and a replacement connection resumes the TLS
/// session from the ticket stored in the shared `tls_config`; early data
/// (0-RTT) stays off. Share one `tls_config` between backends of the same
/// upstream that should share tickets. A pool never shares a connection
/// with another backend, even to the same address.
///
/// A query is sent again, once, on a fresh connection when the pooled
/// connection it used had already answered a query and then failed at the
/// connection level (the server closed or reset it) and the query's opcode
/// is `QUERY`. Timeouts, TLS errors, validation mismatches and undecodable
/// answers are never retried, and the error classes are the ones the
/// backend always returned. A response is accepted only for a query that is
/// waiting for it: a frame that matches no waiting query (for example a
/// response with a different message id) is dropped, so such a reply leaves
/// the query to time out instead of being reported as [`Error::Transport`],
/// and an upstream that sends more than 16 stray frames in a row has its
/// connection closed.
///
/// With reuse enabled the backend starts Tokio tasks and keeps sockets open
/// between queries, so it must be used from one Tokio runtime for its whole
/// life (a pattern that builds a runtime per call must use
/// [`PoolConfig::disabled`]); dropping the backend closes its connections
/// and ends its tasks. One connection then carries the queries of many
/// clients, which the upstream can correlate more easily than one
/// connection per query.
pub struct DotBackend {
    config: DotBackendConfig,
    pool: Option<StreamPool<DotOpen>>,
}

impl DotBackend {
    /// Builds a DoT backend from `config` with connection reuse on
    /// ([`PoolConfig::new`]).
    pub fn new(config: DotBackendConfig) -> Self {
        Self { config, pool: None }.with_pool(PoolConfig::new())
    }

    /// Replaces the connection-reuse policy. [`PoolConfig::disabled`] makes
    /// every query open its own connection, as before connection reuse
    /// existed.
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.is_enabled().then(|| {
            let read = self.config.read_timeout;
            StreamPool::new(
                pool,
                DotOpen {
                    server: self.config.server,
                    server_name: self.config.server_name.clone(),
                    tls_config: Arc::clone(&self.config.tls_config),
                    connect_timeout: self.config.connect_timeout,
                    read_timeout: read,
                },
                read,
                // The longest one call could take without reuse: connect,
                // handshake, write, read.
                self.config
                    .connect_timeout
                    .saturating_add(read.saturating_mul(3)),
            )
        });
        self
    }

    /// A snapshot of the connection pool's counters. All zeros when reuse is
    /// disabled.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        self.pool
            .as_ref()
            .map_or_else(PoolStats::default, StreamPool::stats)
    }
}

/// Connects to the upstream and completes the TLS handshake. `nodelay`
/// disables Nagle's algorithm on the TCP socket (pooled connections send many
/// small pipelined frames).
async fn connect_tls(
    server: SocketAddr,
    server_name: &ServerName<'static>,
    tls_config: &Arc<ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    nodelay: bool,
) -> Result<TlsStream<TcpStream>> {
    let stream = timeout(connect_timeout, TcpStream::connect(server))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
    if nodelay {
        let _ = stream.set_nodelay(true);
    }

    let connector = TlsConnector::from(Arc::clone(tls_config));
    timeout(
        handshake_timeout,
        connector.connect(server_name.clone(), stream),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(map_tls_connect_error)
}

/// Opens the TLS connections of a [`DotBackend`] pool.
struct DotOpen {
    server: SocketAddr,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl StreamOpen for DotOpen {
    type Stream = TlsStream<TcpStream>;

    async fn open(&self) -> Result<Self::Stream> {
        connect_tls(
            self.server,
            &self.server_name,
            &self.tls_config,
            self.connect_timeout,
            self.read_timeout,
            true,
        )
        .await
    }
}

#[async_trait]
impl UpstreamBackend for DotBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        if let Some(pool) = &self.pool {
            return pool.query(query).await;
        }
        let mut tls_stream = connect_tls(
            self.config.server,
            &self.config.server_name,
            &self.config.tls_config,
            self.config.connect_timeout,
            self.config.read_timeout,
            false,
        )
        .await?;

        framed_query(
            &mut tls_stream,
            self.config.read_timeout,
            query,
            IdCheck::Match,
        )
        .await
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::HandshakeKind;
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
    async fn dot_backend_rejects_a_response_with_a_different_id() {
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

            let response = answer_for("example.com", query.header.id.wrapping_add(1));
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

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a DoT response with another id is rejected");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
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

    // ---- pooled DoT over loopback TLS -----------------------------------------

    /// A loopback DoT server that counts TLS handshakes and how many of them
    /// resumed a session. Each connection answers every query at once and,
    /// when `answers_per_connection` is set, hangs up after that many.
    struct TlsServer {
        addr: SocketAddr,
        handshakes: Arc<AtomicUsize>,
        resumed: Arc<AtomicUsize>,
        client_config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    }

    impl TlsServer {
        async fn start(answers_per_connection: Option<usize>) -> Self {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handshakes = Arc::new(AtomicUsize::new(0));
            let resumed = Arc::new(AtomicUsize::new(0));
            let (h, r) = (Arc::clone(&handshakes), Arc::clone(&resumed));
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let (h, r) = (Arc::clone(&h), Arc::clone(&r));
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        h.fetch_add(1, Ordering::SeqCst);
                        if tls.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed) {
                            r.fetch_add(1, Ordering::SeqCst);
                        }
                        serve_tls(&mut tls, answers_per_connection).await;
                    });
                }
            });
            TlsServer {
                addr,
                handshakes,
                resumed,
                client_config: Arc::new(client_config),
                server_name,
            }
        }

        fn backend(&self) -> DotBackend {
            DotBackend::new(DotBackendConfig {
                server: self.addr,
                server_name: self.server_name.clone(),
                tls_config: Arc::clone(&self.client_config),
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(5),
            })
        }

        fn handshakes(&self) -> usize {
            self.handshakes.load(Ordering::SeqCst)
        }

        fn resumed(&self) -> usize {
            self.resumed.load(Ordering::SeqCst)
        }
    }

    async fn serve_tls<S>(stream: &mut S, limit: Option<usize>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut served = 0usize;
        while limit.is_none_or(|n| served < n) {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let mut payload = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            let mut response = Message::decode(&payload).unwrap();
            response.header.qr = true;
            let bytes = response.encode().unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
                return;
            }
            served += 1;
        }
    }

    #[tokio::test]
    async fn pooled_dot_backend_handshakes_once_for_sequential_queries() {
        let server = TlsServer::start(None).await;
        let backend = server.backend();
        for i in 0..5 {
            let name = format!("n{i}.example.com");
            let answer = backend.resolve(&query_for(&name)).await.unwrap();
            assert_eq!(answer.questions, query_for(&name).questions);
            assert_eq!(answer.header.id, 11);
        }
        assert_eq!(server.handshakes(), 1);
        assert_eq!(backend.pool_stats().reused_queries(), 4);
    }

    #[tokio::test]
    async fn a_disabled_dot_pool_handshakes_per_query_and_still_resumes_sessions() {
        let server = TlsServer::start(None).await;
        let backend = server.backend().with_pool(PoolConfig::disabled());
        for i in 0..3 {
            backend
                .resolve(&query_for(&format!("d{i}.example.com")))
                .await
                .unwrap();
        }
        assert_eq!(server.handshakes(), 3);
        assert!(server.resumed() >= 1, "later handshakes resume the session");
        assert_eq!(backend.pool_stats(), PoolStats::default());
    }

    #[tokio::test]
    async fn a_pooled_dot_reconnect_resumes_the_tls_session() {
        let server = TlsServer::start(Some(1)).await;
        let backend = server.backend();
        for i in 0..3 {
            backend
                .resolve(&query_for(&format!("p{i}.example.com")))
                .await
                .unwrap();
        }
        assert_eq!(server.handshakes(), 3);
        assert!(server.resumed() >= 1, "the shared tls config resumes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_concurrent_dot_queries_share_a_few_connections() {
        let server = TlsServer::start(None).await;
        let backend = Arc::new(
            server
                .backend()
                .with_pool(PoolConfig::new().max_connections(2)),
        );
        let calls: Vec<_> = (0..100)
            .map(|i| {
                let backend = Arc::clone(&backend);
                tokio::spawn(async move {
                    let name = format!("c{i}.example.com");
                    let answer = backend.resolve(&query_for(&name)).await.unwrap();
                    assert_eq!(answer.questions, query_for(&name).questions);
                })
            })
            .collect();
        for call in calls {
            call.await.unwrap();
        }
        assert!(
            server.handshakes() <= 2,
            "{} handshakes",
            server.handshakes()
        );
    }

    #[tokio::test]
    async fn a_pooled_dot_answer_with_an_unknown_id_is_dropped_and_the_query_times_out() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await.unwrap();
            let mut payload = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            tls.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();
            let bytes = answer_for("example.com", query.header.id.wrapping_add(1))
                .encode()
                .unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            tls.write_all(&framed).await.unwrap();
            // Stay connected so the client cannot tell from a hang-up.
            let mut rest = Vec::new();
            let _ = tls.read_to_end(&mut rest).await;
        });
        let backend = DotBackend::new(DotBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_millis(400),
        });
        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert_eq!(backend.pool_stats().unsolicited(), 1);
    }
}
