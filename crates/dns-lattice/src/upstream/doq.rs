//! DNS-over-QUIC upstream backend (RFC 9250), behind the `doq` Cargo
//! feature. QUIC transport uses `quinn`, with TLS 1.3
//! (embedded in QUIC itself) via `rustls`, reusing
//! [`super::framed_query`]'s RFC 1035 §4.2.2 2-byte length-prefixed DNS
//! message framing on one bidirectional QUIC stream per query (RFC 9250
//! §4.2), and no 0-RTT for queries (replay-safety, RFC 9250 §4.2).
//!
//! # Connection reuse
//!
//! By default the backend keeps a bounded [`Pool`] of QUIC connections, all
//! opened on one shared `quinn::Endpoint` (see [`super::quic`]), and opens one
//! stream per query on them. QUIC streams are independent, so unlike the
//! stream-pipelining TCP/DoT engine no message-id remapping is needed: the
//! stream is the correlation, the id on the wire stays 0 and the caller's id
//! is restored on the answer.
//!
//! - **Liveness** is `Connection::close_reason`, checked synchronously when a
//!   connection is chosen: a connection the peer closed, the QUIC idle timeout
//!   ended or a stateless reset killed is never handed out.
//! - **Idle** connections are closed by the pool after the configured idle
//!   timeout. The QUIC transport idle timeout is set slightly longer (by
//!   [`TRANSPORT_IDLE_MARGIN`]) so the pool's graceful close wins the race and
//!   is counted as an idle close.
//! - **Rotation.** A connection that reached its maximum lifetime stops taking
//!   queries and is closed once its streams finished (or after the read
//!   timeout), so a replacement is opened without failing a query.
//! - **Failure.** A failure of one stream (the peer reset it, stopped it, or
//!   sent an undecodable or non-matching answer) fails that query only and
//!   leaves the connection in use. A failure that closed the connection marks
//!   it dead; if the connection had already answered a query and the opcode
//!   is `QUERY`, the query is sent once more on a fresh connection.
//! - **Cancellation.** Dropping the `resolve` future aborts its stream with
//!   `DOQ_REQUEST_CANCELLED` (RFC 9250 §4.3) and frees its slot; the
//!   connection is unaffected.
//! - **Shutdown.** Dropping the backend closes every connection with
//!   `DOQ_NO_ERROR` and releases the endpoint.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Message, Opcode};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::ClientConfig as RustlsClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::runtime::Id as RuntimeId;
use tokio::time::{Instant, timeout, timeout_at};

use super::pool::{Connector, Pool, PoolHooks};
use super::quic::{
    NO_ERROR, QuicClient, TRANSPORT_IDLE_MARGIN, connection_error_to_lattice_error,
    unspecified_like,
};
use super::{
    IdCheck, PoolConfig, PoolStats, UpstreamBackend, framed_query, read_framed, validate_response,
};

/// The ALPN protocol identifier for DNS-over-QUIC (RFC 9250 §4.1.1).
const DOQ_ALPN: &[u8] = b"doq";

/// DOQ_REQUEST_CANCELLED (RFC 9250 §4.3): the client abandoned the query.
const REQUEST_CANCELLED: u32 = 3;

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
/// A pre-handshake QUIC/UDP-layer failure
/// (endpoint bind, `Endpoint::connect`, or a post-handshake QUIC transport/
/// stream failure) maps to [`Error::Transport`]; a failure attributable to
/// the QUIC connection's embedded TLS 1.3 handshake maps to [`Error::Tls`].
///
/// # Connection reuse
///
/// By default the backend keeps a small pool of QUIC connections to the
/// upstream, all on one shared UDP socket, and opens one bidirectional stream
/// per query (RFC 9250 §4.2), so a query does not pay a QUIC and TLS
/// handshake. A [`PoolConfig`] passed to [`with_pool`](Self::with_pool) sets
/// the bounds: `max_connections` connections, `max_in_flight` concurrent
/// streams per connection (keep it below the server's own stream limit, which
/// is commonly 100; a query that finds the limit reached waits for a stream
/// and fails with [`Error::Timeout`] at its deadline), the idle timeout and the
/// maximum connection lifetime. [`pool_stats`](Self::pool_stats) reports what
/// the pool did and [`PoolConfig::disabled`] restores one endpoint and one
/// connection per query.
///
/// The handshake of every new connection verifies the server certificate
/// against `server_name` again, and a replacement connection resumes the TLS
/// session from the ticket stored in the shared `tls_config`; early data
/// (0-RTT) stays off. A pool never shares a connection with another backend,
/// even to the same address.
///
/// A query is sent again, once, on a fresh connection when the connection it
/// used had already answered a query and was then closed (by the peer, by an
/// idle timeout or by a reset) and the query's opcode is `QUERY`. A query is
/// not sent again after a timeout, a TLS error, an answer that does not match
/// the question, or a reset of its own stream; those fail only that query and
/// the connection stays in use. The error classes are the ones the backend
/// always returned.
///
/// With reuse enabled the backend starts Tokio tasks (the QUIC endpoint and
/// connection drivers) and keeps a UDP socket open between queries, so it must
/// be used from one Tokio runtime for its whole life (a pattern that builds a
/// runtime per call must use [`PoolConfig::disabled`]); a backend whose runtime
/// was shut down binds a new endpoint on the runtime that calls it next.
/// Dropping the backend closes its connections. One connection then carries
/// the queries of many clients, which the upstream can correlate more easily
/// than one connection per query.
pub struct DoqBackend {
    config: DoqBackendConfig,
    pool: Option<DoqPool>,
}

impl DoqBackend {
    /// Builds a DoQ backend from `config` with connection reuse on
    /// ([`PoolConfig::new`]).
    pub fn new(config: DoqBackendConfig) -> Self {
        Self { config, pool: None }.with_pool(PoolConfig::new())
    }

    /// Replaces the connection-reuse policy. [`PoolConfig::disabled`] makes
    /// every query bind its own endpoint and open its own connection, as
    /// before connection reuse existed.
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.is_enabled().then(|| {
            let connect = self.config.connect_timeout;
            let read = self.config.read_timeout;
            let client = QuicClient::new(
                self.config.server,
                &self.config.server_name.to_str(),
                &self.config.tls_config,
                Some(
                    pool.idle_timeout_value()
                        .saturating_add(TRANSPORT_IDLE_MARGIN),
                ),
                connect,
            );
            DoqPool {
                pool: Pool::new(pool, Arc::new(DoqConnector { client }), read),
                read_timeout: read,
                // The longest one call could take without reuse: connect,
                // open the stream, write, read.
                call_budget: connect
                    .saturating_mul(2)
                    .saturating_add(read.saturating_mul(2)),
            }
        });
        self
    }

    /// A snapshot of the connection pool's counters. All zeros when reuse is
    /// disabled. `unsolicited` is always 0 (a QUIC stream carries exactly
    /// the answer to its own query).
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        self.pool
            .as_ref()
            .map_or_else(PoolStats::default, DoqPool::stats)
    }
}

/// The QUIC connections of a [`DoqBackend`] pool.
struct DoqConnector {
    client: QuicClient,
}

/// One pooled QUIC connection.
struct DoqConn {
    connection: Connection,
    /// The runtime that opened it; a connection whose runtime is gone has lost
    /// its driver tasks and can never carry another query.
    runtime: Option<RuntimeId>,
    /// The connection has answered at least one query.
    answered: AtomicBool,
}

impl Connector for DoqConnector {
    type Conn = DoqConn;

    async fn connect(&self, _hooks: PoolHooks) -> Result<DoqConn> {
        let connection = self.client.connect().await?;
        Ok(DoqConn {
            connection,
            runtime: QuicClient::current_runtime(),
            answered: AtomicBool::new(false),
        })
    }

    fn is_alive(&self, conn: &DoqConn) -> bool {
        conn.connection.close_reason().is_none()
            && QuicClient::current_runtime()
                .is_none_or(|now| conn.runtime.is_none_or(|opened| opened == now))
    }

    fn close(&self, conn: &DoqConn) {
        conn.connection.close(VarInt::from_u32(NO_ERROR), &[]);
    }
}

/// A failed attempt and whether the retry rule allows another one.
struct AttemptError {
    error: Error,
    retry: bool,
}

impl AttemptError {
    fn final_(error: Error) -> Self {
        AttemptError {
            error,
            retry: false,
        }
    }
}

/// Aborts a query's stream with `DOQ_REQUEST_CANCELLED` unless the query
/// completed, so a cancelled, timed out or failed query frees its stream.
struct StreamGuard {
    stream: QuicStream,
    done: bool,
}

impl StreamGuard {
    /// The query completed: close the send side gracefully (RFC 9250 §4.2).
    fn finish(mut self) {
        self.done = true;
        let _ = self.stream.send.finish();
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if !self.done {
            let code = VarInt::from_u32(REQUEST_CANCELLED);
            let _ = self.stream.send.reset(code);
            let _ = self.stream.recv.stop(code);
        }
    }
}

/// The pooled client of one DoQ upstream.
struct DoqPool {
    pool: Pool<DoqConnector>,
    /// How long opening a stream, writing and reading may each take.
    read_timeout: Duration,
    /// The longest one call may take in total, retry included.
    call_budget: Duration,
}

impl DoqPool {
    /// The pool's counters, after retiring connections that have died.
    fn stats(&self) -> PoolStats {
        self.pool.sweep();
        self.pool.stats()
    }

    /// Sends `query` on a pooled connection and returns the answer, with the
    /// caller's message id restored.
    async fn query(&self, query: &Message) -> Result<Message> {
        // RFC 9250 §4.2.1: the message id on the wire MUST be 0.
        let mut wire_query = query.clone();
        wire_query.header.id = 0;
        let payload = wire_query.encode()?;
        let len = u16::try_from(payload.len()).map_err(|_| Error::MessageTooLong)?;
        let mut framed = Vec::with_capacity(payload.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&payload);

        let now = Instant::now();
        let deadline = now
            .checked_add(self.call_budget)
            .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365));
        let mut fresh = false;
        loop {
            match self.attempt(&framed, query, deadline, fresh).await {
                Ok(answer) => return Ok(answer),
                Err(failed) => {
                    if failed.retry && !fresh && Instant::now() < deadline {
                        self.pool.record_retry();
                        fresh = true;
                        continue;
                    }
                    return Err(failed.error);
                }
            }
        }
    }

    async fn attempt(
        &self,
        framed: &[u8],
        query: &Message,
        deadline: Instant,
        fresh: bool,
    ) -> std::result::Result<Message, AttemptError> {
        let lease = if fresh {
            self.pool.acquire_fresh(deadline).await
        } else {
            self.pool.acquire(deadline).await
        }
        .map_err(AttemptError::final_)?;
        let conn = Arc::clone(lease.conn());
        // The failure of one stream leaves the connection alone. Only a
        // failure that closed the connection retires it, and only a
        // connection that had answered before (so the failure may be a stale
        // pooled connection) justifies sending a safe query again.
        let failed = |error: Error| {
            let closed = conn.connection.close_reason().is_some();
            if closed {
                lease.mark_dead();
            }
            AttemptError {
                retry: closed
                    && conn.answered.load(Ordering::Relaxed)
                    && matches!(query.header.opcode, Opcode::Query),
                error,
            }
        };

        let open_until = Instant::now()
            .checked_add(self.read_timeout)
            .map_or(deadline, |t| t.min(deadline));
        // Opening a stream only waits when the peer's stream limit is
        // reached, which says nothing about the connection's health.
        let (send, recv) = match timeout_at(open_until, conn.connection.open_bi()).await {
            Err(_) => return Err(AttemptError::final_(Error::Timeout)),
            Ok(Err(err)) => return Err(failed(connection_error_to_lattice_error(err))),
            Ok(Ok(pair)) => pair,
        };
        let mut guard = StreamGuard {
            stream: QuicStream { send, recv },
            done: false,
        };
        let exchanged = timeout_at(deadline, async {
            timeout(self.read_timeout, guard.stream.write_all(framed))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|err| Error::Transport(err.to_string()))?;
            let answer = read_framed(&mut guard.stream, self.read_timeout).await?;
            validate_response(query, &answer, IdCheck::Ignore)?;
            Ok::<Message, Error>(answer)
        })
        .await;
        match exchanged {
            Err(_) | Ok(Err(Error::Timeout)) => {
                drop(guard);
                lease.note_timeout();
                Err(AttemptError::final_(Error::Timeout))
            }
            Ok(Err(err)) => {
                drop(guard);
                Err(failed(err))
            }
            Ok(Ok(mut answer)) => {
                guard.finish();
                answer.header.id = query.header.id;
                conn.answered.store(true, Ordering::Relaxed);
                lease.complete();
                Ok(answer)
            }
        }
    }
}

#[async_trait]
impl UpstreamBackend for DoqBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        match &self.pool {
            Some(pool) => pool.query(query).await,
            None => self.resolve_unpooled(query).await,
        }
    }
}

impl DoqBackend {
    /// One endpoint, one connection and one stream per call.
    async fn resolve_unpooled(&self, query: &Message) -> Result<Message> {
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

        // RFC 9250 §4.2.1: the message id on the wire MUST be 0. The
        // caller's id is put back on the response below.
        let mut wire_query = query.clone();
        wire_query.header.id = 0;

        let mut stream = QuicStream { send, recv };
        let response = framed_query(
            &mut stream,
            self.config.read_timeout,
            &wire_query,
            IdCheck::Ignore,
        )
        .await
        .map(|mut response| {
            response.header.id = query.header.id;
            response
        });

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

    /// Accepts one QUIC connection and one bidirectional stream, reads one
    /// framed query, and answers it with `respond(query)`.
    async fn serve_one_doq_response(endpoint: Endpoint, respond: fn(&Message) -> Message) {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (mut send, mut recv) = connection.accept_bi().await.unwrap();

        let mut len_buf = [0u8; 2];
        recv.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload).await.unwrap();
        let query = Message::decode(&payload).unwrap();

        let bytes = respond(&query).encode().unwrap();
        let framed_len: u16 = bytes.len().try_into().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&framed_len.to_be_bytes());
        framed.extend_from_slice(&bytes);
        send.write_all(&framed).await.unwrap();
        let _ = send.finish();
        // See `doq_backend_resolves_against_a_loopback_quic_server`: keep
        // the connection alive until the client has read the response.
        let _ = send.stopped().await;
    }

    #[tokio::test]
    async fn doq_backend_accepts_a_response_with_id_zero() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        // RFC 9250 §4.2.1 puts message id 0 on the wire; the id is not
        // compared for DoQ, only QR and the question.
        let responder = tokio::spawn(serve_one_doq_response(endpoint, |query| {
            assert_eq!(query.header.id, 0, "a DoQ query is sent with id 0");
            answer_for("EXAMPLE.com", 0)
        }));

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
            .expect("a DoQ response with id 0 and a matching question is accepted");
        assert!(answer.header.qr);
        // The caller's query id is restored on the returned response.
        assert_eq!(answer.header.id, query_for("example.com").header.id);
        assert_ne!(answer.header.id, 0);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doq_backend_rejects_a_response_for_a_different_question() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doq_response(endpoint, |_query| {
            answer_for("example.org", 0)
        }));

        let backend = DoqBackend::new(DoqBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a DoQ response for another question is rejected");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
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

    // ---- connection reuse ------------------------------------------------

    use std::sync::atomic::AtomicUsize;
    use tokio::task::JoinSet;
    use tokio::time::sleep;

    /// What the scripted responder does with one query.
    enum Action {
        /// Answers with this message.
        Reply(Message),
        /// Echoes the query as an answer after a delay (or until the client
        /// stops the stream).
        ReplyAfter(Duration),
        /// Echoes the query, then closes the connection.
        ReplyThenClose,
        /// Closes the connection without answering.
        Close,
        /// Never answers; waits for the client to give up on the stream.
        Hold,
    }

    /// The echo of `query` as an answer, with message id 0 (RFC 9250 §4.2.1).
    fn echo(query: &Message) -> Message {
        let mut answer = query.clone();
        answer.header.qr = true;
        answer.header.id = 0;
        answer
    }

    #[derive(Default)]
    struct Counters {
        /// Connections whose handshake completed.
        accepted: AtomicUsize,
        /// Connections that ended.
        closed: AtomicUsize,
        /// Streams being served right now.
        active: AtomicUsize,
        /// The most streams served at once.
        max_active: AtomicUsize,
        /// Streams the client stopped before they were answered.
        cancelled: AtomicUsize,
        /// The code of the last such stop.
        cancel_code: AtomicUsize,
    }

    impl Counters {
        fn get(counter: &AtomicUsize) -> usize {
            counter.load(Ordering::SeqCst)
        }
    }

    /// A loopback DoQ responder driven by a script of
    /// `(connection index, stream index on that connection, query) -> Action`.
    struct Scripted {
        addr: SocketAddr,
        counters: Arc<Counters>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Scripted {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    type Script = Arc<dyn Fn(usize, usize, &Message) -> Action + Send + Sync>;

    fn serve(
        server_config: ServerConfig,
        script: impl Fn(usize, usize, &Message) -> Action + Send + Sync + 'static,
    ) -> Scripted {
        let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let script: Script = Arc::new(script);
        let counters = Arc::new(Counters::default());
        let shared = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            let mut next_connection = 0;
            while let Some(incoming) = endpoint.accept().await {
                let index = next_connection;
                next_connection += 1;
                let script = Arc::clone(&script);
                let counters = Arc::clone(&shared);
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    counters.accepted.fetch_add(1, Ordering::SeqCst);
                    let mut next_stream = 0;
                    while let Ok((send, recv)) = connection.accept_bi().await {
                        let stream = next_stream;
                        next_stream += 1;
                        tokio::spawn(serve_stream(
                            connection.clone(),
                            send,
                            recv,
                            Arc::clone(&script),
                            (index, stream),
                            Arc::clone(&counters),
                        ));
                    }
                    counters.closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Scripted {
            addr,
            counters,
            task,
        }
    }

    fn note_cancel(
        stopped: std::result::Result<Option<VarInt>, quinn::StoppedError>,
        counters: &Counters,
    ) {
        if let Ok(Some(code)) = stopped {
            let code = usize::try_from(code.into_inner()).unwrap();
            counters.cancel_code.store(code, Ordering::SeqCst);
            counters.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn serve_stream(
        connection: Connection,
        mut send: SendStream,
        mut recv: RecvStream,
        script: Script,
        (connection_index, stream_index): (usize, usize),
        counters: Arc<Counters>,
    ) {
        let mut len = [0u8; 2];
        if recv.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut payload = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if recv.read_exact(&mut payload).await.is_err() {
            return;
        }
        let query = Message::decode(&payload).unwrap();
        let now = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
        counters.max_active.fetch_max(now, Ordering::SeqCst);
        let mut close_after = false;
        let reply = match script(connection_index, stream_index, &query) {
            Action::Reply(message) => Some(message),
            Action::ReplyThenClose => {
                close_after = true;
                Some(echo(&query))
            }
            Action::ReplyAfter(delay) => {
                tokio::select! {
                    () = sleep(delay) => Some(echo(&query)),
                    stopped = send.stopped() => {
                        note_cancel(stopped, &counters);
                        None
                    }
                }
            }
            Action::Close => {
                connection.close(VarInt::from_u32(7), b"scripted close");
                None
            }
            Action::Hold => {
                note_cancel(send.stopped().await, &counters);
                None
            }
        };
        if let Some(reply) = reply {
            let bytes = reply.encode().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
            framed.extend_from_slice(&bytes);
            if send.write_all(&framed).await.is_ok() {
                let _ = send.finish();
                let _ = send.stopped().await;
            }
            if close_after {
                connection.close(VarInt::from_u32(0), b"done");
            }
        }
        counters.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Waits (bounded) until `condition` holds.
    async fn eventually(what: &str, condition: impl Fn() -> bool) {
        for _ in 0..300 {
            if condition() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    fn backend_for(
        addr: SocketAddr,
        client_config: RustlsClientConfig,
        server_name: ServerName<'static>,
        pool: PoolConfig,
    ) -> DoqBackend {
        DoqBackend::new(DoqBackendConfig {
            server: addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        })
        .with_pool(pool)
    }

    fn echo_server() -> (Scripted, DoqBackend) {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::ReplyAfter(Duration::ZERO));
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        (server, backend)
    }

    #[tokio::test]
    async fn sequential_queries_share_one_connection() {
        let (server, backend) = echo_server();
        for i in 0..5 {
            let mut query = query_for(&format!("q{i}.example.com"));
            query.header.id = 100 + i;
            let answer = backend.resolve(&query).await.expect("answered");
            assert_eq!(answer.header.id, 100 + i, "the caller's id is restored");
            assert_eq!(answer.questions, query.questions);
        }
        let stats = backend.pool_stats();
        assert_eq!(Counters::get(&server.counters.accepted), 1);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.queries(), 5);
        assert_eq!(stats.reused_queries(), 4);
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.in_flight(), 0);
    }

    #[tokio::test]
    async fn disabled_pool_opens_one_connection_per_query() {
        // Negative control for the reuse test above.
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::ReplyAfter(Duration::ZERO));
        let backend = backend_for(
            server.addr,
            client_config,
            server_name,
            PoolConfig::disabled(),
        );
        for i in 0..3 {
            backend
                .resolve(&query_for(&format!("q{i}.example.com")))
                .await
                .expect("answered");
        }
        assert_eq!(Counters::get(&server.counters.accepted), 3);
        assert_eq!(backend.pool_stats(), PoolStats::default());
    }

    #[tokio::test]
    async fn concurrent_queries_get_their_own_answers_within_the_connection_bound() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| {
            Action::ReplyAfter(Duration::from_millis(30))
        });
        let backend = Arc::new(backend_for(
            server.addr,
            client_config,
            server_name,
            PoolConfig::new().max_connections(2),
        ));
        let mut tasks = JoinSet::new();
        for i in 0..40u16 {
            let backend = Arc::clone(&backend);
            tasks.spawn(async move {
                let mut query = query_for(&format!("host{i}.example.com"));
                query.header.id = 1000 + i;
                let answer = backend.resolve(&query).await.expect("answered");
                assert_eq!(answer.header.id, 1000 + i);
                assert_eq!(answer.questions, query.questions);
            });
        }
        while let Some(done) = tasks.join_next().await {
            done.unwrap();
        }
        let stats = backend.pool_stats();
        assert!(Counters::get(&server.counters.accepted) <= 2);
        assert!(stats.connections_opened() <= 2, "{stats:?}");
        assert_eq!(stats.queries(), 40);
        assert_eq!(stats.in_flight(), 0);
        // Streams really ran side by side (one stream per query, not one
        // query at a time).
        assert!(Counters::get(&server.counters.max_active) > 2);
    }

    #[tokio::test]
    async fn max_in_flight_bounds_the_streams_and_queues_the_rest() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| {
            Action::ReplyAfter(Duration::from_millis(30))
        });
        let backend = Arc::new(backend_for(
            server.addr,
            client_config,
            server_name,
            PoolConfig::new().max_connections(1).max_in_flight(2),
        ));
        let mut tasks = JoinSet::new();
        for i in 0..8u16 {
            let backend = Arc::clone(&backend);
            tasks.spawn(async move {
                backend
                    .resolve(&query_for(&format!("host{i}.example.com")))
                    .await
                    .expect("answered");
            });
        }
        while let Some(done) = tasks.join_next().await {
            done.unwrap();
        }
        assert!(Counters::get(&server.counters.max_active) <= 2);
        assert_eq!(Counters::get(&server.counters.accepted), 1);
        assert!(backend.pool_stats().queued() > 0);
    }

    #[tokio::test]
    async fn a_connection_closed_while_serving_is_retried_once_on_a_fresh_one() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        // The first connection answers one query and drops the second.
        let server = serve(server_config, |connection, stream, _| {
            if connection == 0 && stream == 1 {
                Action::Close
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        let answer = backend
            .resolve(&query_for("two.example.com"))
            .await
            .expect("the retry on a fresh connection answers");
        assert_eq!(answer.questions, query_for("two.example.com").questions);
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 1);
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(Counters::get(&server.counters.accepted), 2);
    }

    #[tokio::test]
    async fn a_fresh_connection_that_closes_is_not_retried() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::Close);
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        let err = backend
            .resolve(&query_for("one.example.com"))
            .await
            .expect_err("a closed connection fails the query");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(Counters::get(&server.counters.accepted), 1);
    }

    #[tokio::test]
    async fn a_failing_retry_returns_the_transport_error() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |connection, stream, _| {
            if connection == 0 && stream == 0 {
                Action::ReplyAfter(Duration::ZERO)
            } else {
                Action::Close
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        let err = backend
            .resolve(&query_for("two.example.com"))
            .await
            .expect_err("the retry fails too");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 1, "retried exactly once");
        assert_eq!(Counters::get(&server.counters.accepted), 2);
    }

    #[tokio::test]
    async fn a_non_query_opcode_is_not_retried() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |connection, stream, _| {
            if connection == 0 && stream == 1 {
                Action::Close
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        let mut notify = query_for("two.example.com");
        notify.header.opcode = Opcode::Notify;
        let err = backend
            .resolve(&notify)
            .await
            .expect_err("a NOTIFY is never resent");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(Counters::get(&server.counters.accepted), 1);
    }

    #[tokio::test]
    async fn a_connection_the_peer_already_closed_is_replaced_without_a_retry() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |connection, _, _| {
            if connection == 0 {
                Action::ReplyThenClose
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        eventually("the server closed the first connection", || {
            Counters::get(&server.counters.closed) == 1
        })
        .await;
        // The client learns of the close from the peer's frame.
        eventually("the client noticed the close", || {
            backend.pool_stats().connections_open() == 0
        })
        .await;
        backend
            .resolve(&query_for("two.example.com"))
            .await
            .unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0, "liveness is checked before use");
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_error(), 1);
    }

    #[tokio::test]
    async fn a_cancelled_query_resets_its_stream_and_keeps_the_connection() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, stream, _| {
            if stream == 0 {
                Action::Hold
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        let cancelled = tokio::time::timeout(
            Duration::from_millis(150),
            backend.resolve(&query_for("held.example.com")),
        )
        .await;
        assert!(cancelled.is_err(), "the held query was dropped");
        eventually("the server saw the stream stopped", || {
            Counters::get(&server.counters.cancelled) == 1
        })
        .await;
        assert_eq!(
            Counters::get(&server.counters.cancel_code),
            usize::try_from(REQUEST_CANCELLED).unwrap(),
            "DOQ_REQUEST_CANCELLED"
        );
        assert_eq!(backend.pool_stats().in_flight(), 0);
        backend
            .resolve(&query_for("next.example.com"))
            .await
            .expect("the connection is still usable");
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(Counters::get(&server.counters.accepted), 1);
    }

    #[tokio::test]
    async fn a_timed_out_query_is_not_retried() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, stream, _| {
            if stream == 1 {
                Action::Hold
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = DoqBackend::new(DoqBackendConfig {
            server: server.addr,
            server_name,
            tls_config: Arc::new(client_config),
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_millis(200),
        });
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        let err = backend
            .resolve(&query_for("two.example.com"))
            .await
            .expect_err("an unanswered query times out");
        assert_eq!(err, Error::Timeout);
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(
            stats.connections_open(),
            1,
            "one timeout keeps the connection"
        );
    }

    #[tokio::test]
    async fn a_mismatched_answer_fails_only_its_query() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, query| {
            if query.questions[0].name == Name::from_ascii("bad.example.com").unwrap() {
                Action::Reply(answer_for("other.example.org", 0))
            } else {
                Action::ReplyAfter(Duration::ZERO)
            }
        });
        let backend = backend_for(server.addr, client_config, server_name, PoolConfig::new());
        let err = backend
            .resolve(&query_for("bad.example.com"))
            .await
            .expect_err("the answer is for another question");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        backend
            .resolve(&query_for("good.example.com"))
            .await
            .expect("the same connection still works");
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.closed_error(), 0);
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_after_the_idle_timeout() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::ReplyAfter(Duration::ZERO));
        let backend = backend_for(
            server.addr,
            client_config,
            server_name,
            PoolConfig::new().idle_timeout(Duration::from_secs(1)),
        );
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        assert_eq!(backend.pool_stats().connections_open(), 1);
        sleep(Duration::from_millis(1400)).await;
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(stats.closed_idle(), 1);
        eventually("the server saw the close", || {
            Counters::get(&server.counters.closed) == 1
        })
        .await;
        backend
            .resolve(&query_for("two.example.com"))
            .await
            .unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.retries(), 0);
    }

    #[tokio::test]
    async fn a_connection_rotates_at_its_maximum_lifetime() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::ReplyAfter(Duration::ZERO));
        let backend = backend_for(
            server.addr,
            client_config,
            server_name,
            PoolConfig::new().max_lifetime(Some(Duration::from_secs(1))),
        );
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        sleep(Duration::from_millis(1200)).await;
        backend
            .resolve(&query_for("two.example.com"))
            .await
            .expect("the replacement answers without a failed query");
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_lifetime(), 1);
        assert_eq!(stats.retries(), 0);
    }

    #[tokio::test]
    async fn dropping_the_backend_closes_its_connection() {
        let (server, backend) = echo_server();
        backend
            .resolve(&query_for("one.example.com"))
            .await
            .unwrap();
        assert_eq!(Counters::get(&server.counters.closed), 0);
        drop(backend);
        eventually("the server saw the close", || {
            Counters::get(&server.counters.closed) == 1
        })
        .await;
    }

    #[tokio::test]
    async fn two_backends_never_share_a_connection() {
        let (server_config, client_config, server_name) = self_signed_fixture();
        let server = serve(server_config, |_, _, _| Action::ReplyAfter(Duration::ZERO));
        let tls = Arc::new(client_config);
        let make = || {
            DoqBackend::new(DoqBackendConfig {
                server: server.addr,
                server_name: server_name.clone(),
                tls_config: Arc::clone(&tls),
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
            })
        };
        let (first, second) = (make(), make());
        first.resolve(&query_for("one.example.com")).await.unwrap();
        second.resolve(&query_for("one.example.com")).await.unwrap();
        assert_eq!(Counters::get(&server.counters.accepted), 2);
    }
}
