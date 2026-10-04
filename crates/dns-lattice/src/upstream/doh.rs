//! DNS-over-HTTPS upstream backend (RFC 8484), behind the `doh` Cargo
//! feature. HTTP transport via `hyper`/`hyper-rustls` (coupled to the same
//! `rustls` TLS stack the `dot` feature uses) negotiates HTTP/1.1 or HTTP/2
//! through TLS ALPN, and supports the GET wire format (RFC 8484 §4.1's
//! base64url `dns` query parameter) and the POST wire format
//! (`application/dns-message` body) on either HTTP version.
//!
//! # Connection reuse
//!
//! [`DohBackend`] keeps one long-lived HTTP client for its whole life, so the
//! TCP and TLS connections it opens are reused by later queries. Over HTTP/2
//! (the usual case, chosen by TLS ALPN) the queries of all callers are
//! multiplexed as concurrent streams of a single connection; over HTTP/1.1
//! each in-flight query needs a connection of its own and idle connections
//! are kept for later queries. Reuse is bounded by a [`PoolConfig`]; see
//! [`DohBackend::with_pool`]. [`Doh3Backend`] keeps a bounded pool of
//! HTTP/3 connections on one QUIC endpoint and sends each query as its own
//! request (a QUIC stream) on them; see [`Doh3Backend::with_pool`].

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Buf;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Message, Opcode};
use http::{Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::sync::{Notify, Semaphore, TryAcquireError};
use tokio::time::{Instant, timeout, timeout_at};
use tower_service::Service;

use h3::error::{Code as H3Code, StreamError as H3StreamError};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use tokio::runtime::Id as RuntimeId;

use super::pool::{AbortOnDrop, Connector, Pool, PoolHooks};
use super::quic::{NO_ERROR, QuicClient, TRANSPORT_IDLE_MARGIN};
use super::{IdCheck, PoolConfig, PoolStats, UpstreamBackend, validate_response};

/// The DoH request's HTTP method (RFC 8484 §4.1). Both wire formats carry
/// the DNS query in `application/dns-message` wire format; they differ
/// only in how the request body is transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohMethod {
    /// GET with the base64url-encoded query in the `dns` URI query
    /// parameter (RFC 8484 §4.1, second bullet).
    Get,
    /// POST with the raw wire-format query as the request body and
    /// `content-type: application/dns-message` (RFC 8484 §4.1, first
    /// bullet).
    Post,
}

/// Configuration for [`DohBackend`].
#[derive(Clone)]
pub struct DohBackendConfig {
    /// The DoH endpoint URI, e.g. `https://dns.example/dns-query`.
    pub uri: Uri,
    /// Which RFC 8484 wire format to use for each request.
    pub method: DohMethod,
    /// The `rustls` client configuration used to establish the
    /// HTTPS connection's TLS session.
    pub tls_config: Arc<ClientConfig>,
    /// Bounds the whole request (connect, TLS handshake, send, and
    /// receive the response).
    pub timeout: Duration,
}

/// DNS-over-HTTPS upstream backend (RFC 8484), gated behind the `doh`
/// Cargo feature. Follows the same `Config` + `Backend` +
/// `#[async_trait] impl UpstreamBackend` pattern as [`super::UdpBackend`]/
/// [`super::TcpBackend`]/`DotBackend`; adds no fields
/// or methods to the [`UpstreamBackend`] trait itself.
///
/// TLS-layer failures during the underlying HTTPS connection map to
/// [`Error::Tls`]; HTTP-level failures (non-2xx status, malformed
/// `application/dns-message` body, or a connection-level failure below
/// TLS as surfaced by `hyper`) map to [`Error::Transport`]. Expiry of
/// `timeout` is [`Error::Timeout`].
///
/// # Connection reuse
///
/// By default the backend builds one HTTP client when it is created and uses
/// it for every query, so TCP and TLS connections are reused instead of being
/// set up for each query (TLS session resumption still depends on the
/// `tls_config` the caller supplies). A [`PoolConfig`] passed to
/// [`with_pool`](Self::with_pool) bounds the reuse and
/// [`pool_stats`](Self::pool_stats) reports it; [`PoolConfig::disabled`]
/// restores a new client, and so a new connection, for every query.
///
/// - **HTTP/2** (selected by TLS ALPN): the queries of all callers are
///   concurrent streams of one connection, so `max_connections` does not
///   multiply connections; the client keeps one connection to the endpoint
///   and opens a replacement when it fails or is retired. The server's
///   stream limit applies, and further streams wait inside the client.
/// - **HTTP/1.1**: a connection carries one query at a time, so up to
///   `max_connections x max_in_flight` connections can be open while that
///   many queries are in flight; idle ones are kept for later queries up to
///   the same bound.
///
/// At most `max_connections x max_in_flight` queries are in flight at once;
/// further callers wait in arrival order and fail with [`Error::Timeout`]
/// when their `timeout` passes. One `timeout` bounds a whole call, including
/// the wait for admission, the connection setup, the response body and a
/// retry. A connection that has been idle for the pool's idle timeout is
/// closed, and a client older than the maximum lifetime is replaced: new
/// queries use a new client (a new connection, so the server certificate is
/// verified and the host resolved again) and the old one closes as soon as
/// its last query ends. Idle HTTP/2 connections are not pinged; while
/// queries are in flight the client sends HTTP/2 keep-alive pings so a
/// connection that stopped answering is detected.
///
/// A query is sent again, once, when the connection it used had already
/// answered a query and then failed after the request was handed to it (the
/// server closed or reset it, `GOAWAY`), the query's opcode is `QUERY` and
/// the call's `timeout` has not passed. A timeout, a TLS error, a non-2xx
/// status, an undecodable or mismatching answer, and a failure of a
/// connection that had not answered anything are never retried. A bad answer
/// to one query affects only that query. The resend may be served by another
/// idle connection of the pool (HTTP/1.1).
///
/// Pooled sockets have `TCP_NODELAY` set. The client cannot tell HTTP/1.1
/// from HTTP/2 before the first TLS handshake has negotiated ALPN, so while a
/// client has no connection (at the first query, after the connections went
/// idle, and when the client is replaced at the maximum lifetime) one call
/// starts the connection and the calls that arrive meanwhile wait for it.
/// They are released when that call's response headers arrive, not when its
/// connection opens: if that first query is slow or never answered, the
/// waiting calls stay parked until it completes or until their own `timeout`
/// passes.
///
/// The TLS configuration, SNI host and ALPN are fixed when the backend is
/// created: every connection of a backend goes to the one configured
/// endpoint and two backends never share a connection. With reuse enabled
/// one connection carries the queries of many clients, so the upstream can
/// correlate them more easily than with one connection per query.
///
/// A backend with reuse enabled must stay on one Tokio runtime for its life,
/// since the client's connection tasks run on the runtime that first used
/// it; a pattern that builds a runtime for each call must use
/// [`PoolConfig::disabled`]. A pool whose runtime has shut down finds its
/// connections dead and reconnects on the next one. Dropping the backend
/// closes its connections.
pub struct DohBackend {
    config: DohBackendConfig,
    pool: Option<DohPool>,
}

/// Configuration for [`Doh3Backend`], the HTTP/3-over-QUIC DoH transport.
///
/// HTTP/3 uses UDP/QUIC and TLS 1.3; use [`DohBackendConfig`] for legacy
/// TCP HTTPS clients requiring HTTP/1.1 or HTTP/2 with TLS 1.2 support.
#[derive(Clone)]
pub struct Doh3BackendConfig {
    /// The HTTPS DoH endpoint URI. Its host is used for SNI and its path is
    /// used for the RFC 8484 request target.
    pub uri: Uri,
    /// The resolved UDP socket address of the HTTP/3 endpoint.
    pub server: std::net::SocketAddr,
    /// Which RFC 8484 wire format to use.
    pub method: DohMethod,
    /// TLS trust and client-auth configuration. HTTP/3 fixes ALPN to `h3`.
    pub tls_config: Arc<ClientConfig>,
    /// Bounds QUIC connection setup and the complete HTTP/3 request.
    pub timeout: Duration,
}

/// DNS-over-HTTPS over HTTP/3 (RFC 9114) and QUIC, gated by `doh`.
///
/// This is deliberately separate from [`DohBackend`]: HTTP/3 is UDP/QUIC
/// with TLS 1.3, while [`DohBackend`] preserves TCP HTTP/1.1/HTTP/2 support
/// for legacy clients and TLS 1.2 deployments.
///
/// A QUIC TLS alert is reported as [`Error::Tls`]. A non-success HTTP
/// status, a peer closing the negotiated connection, and other non-TLS QUIC
/// or HTTP/3 failures are [`Error::Transport`]; expiry of `timeout` is
/// [`Error::Timeout`].
///
/// # Connection reuse
///
/// By default the backend keeps a small pool of HTTP/3 connections to the
/// upstream, all on one shared UDP socket, and sends every query as its own
/// request, so a query does not pay a QUIC and TLS handshake and the requests
/// of all callers are multiplexed over the connections' streams. A
/// [`PoolConfig`] passed to [`with_pool`](Self::with_pool) sets the bounds:
/// `max_connections` connections, `max_in_flight` concurrent requests per
/// connection (keep it below the server's own stream limit, which is commonly
/// 100; a query that finds the limit reached waits for a stream and fails with
/// [`Error::Timeout`] at its deadline), the idle timeout and the maximum
/// connection lifetime. [`pool_stats`](Self::pool_stats) reports what the pool
/// did and [`PoolConfig::disabled`] restores one endpoint and one connection
/// per query.
///
/// One `timeout` bounds a whole call, including the wait for capacity, the
/// connection setup, the response body and a retry. The handshake of every new
/// connection verifies the server certificate against the URI host again, and
/// a replacement connection resumes the TLS session from the ticket stored in
/// the `tls_config` (the same session store is used for every connection;
/// early data (0-RTT) stays off). A pool never shares a connection with another
/// backend, even to the same address.
///
/// A query is sent again, once, on a fresh connection when the connection it
/// used had already answered a query and was then closed (by the peer, by an
/// idle timeout, by a reset or by `GOAWAY`), the query's opcode is `QUERY` and
/// the call's `timeout` has not passed. A query is not sent again after a
/// timeout, a TLS error, a non-2xx status, an answer that does not match the
/// question, a reset of its own request stream, or a failure of a connection
/// that had not answered anything; those fail only that query and a healthy
/// connection stays in use. The error classes are the ones the backend always
/// returned. Dropping the `resolve` future, or its `timeout` expiring, cancels
/// the request (its stream is reset and the server told to stop sending) and
/// frees its slot; the connection is unaffected. The cancellation carries
/// `H3_REQUEST_CANCELLED` (RFC 9114 §4.1.1); only when the call was already
/// waiting for the answer does the QUIC layer end the answer's direction with
/// error code 0 instead.
///
/// With reuse enabled the backend starts Tokio tasks (the QUIC endpoint and
/// connection drivers) and keeps a UDP socket open between queries, so it must
/// be used from one Tokio runtime for its whole life (a pattern that builds a
/// runtime per call must use [`PoolConfig::disabled`]); a backend whose
/// runtime was shut down binds a new endpoint on the runtime that calls it
/// next. Dropping the backend closes its connections. One connection then
/// carries the queries of many clients, which the upstream can correlate more
/// easily than one connection per query.
pub struct Doh3Backend {
    config: Doh3BackendConfig,
    /// `config.tls_config` with the ALPN fixed to `h3`, built once. It shares
    /// the caller's TLS session store.
    tls_config: Arc<ClientConfig>,
    pool: Option<Doh3Pool>,
}

impl Doh3Backend {
    /// Builds an HTTP/3 DoH backend from `config` with connection reuse on
    /// ([`PoolConfig::new`]).
    pub fn new(config: Doh3BackendConfig) -> Self {
        let mut tls_config = (*config.tls_config).clone();
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        Self {
            config,
            tls_config: Arc::new(tls_config),
            pool: None,
        }
        .with_pool(PoolConfig::new())
    }

    /// Replaces the connection-reuse policy. [`PoolConfig::disabled`] makes
    /// every query bind its own endpoint and open its own connection, as
    /// before connection reuse existed.
    ///
    /// `max_connections` bounds the connections, `max_in_flight` the
    /// concurrent requests on each, `idle_timeout` closes idle connections and
    /// `max_lifetime` rotates them (a connection past its lifetime takes no new
    /// queries and is closed once its requests finished).
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.is_enabled().then(|| {
            let timeout = self.config.timeout;
            let client = QuicClient::new(
                self.config.server,
                self.config.uri.host().unwrap_or_default(),
                &self.tls_config,
                Some(
                    pool.idle_timeout_value()
                        .saturating_add(TRANSPORT_IDLE_MARGIN),
                ),
                timeout,
            );
            Doh3Pool {
                pool: Pool::new(pool, Arc::new(Doh3Connector { client, timeout }), timeout),
                uri: self.config.uri.clone(),
                method: self.config.method,
                timeout,
            }
        });
        self
    }

    /// A snapshot of the connection pool's counters. All zeros when reuse is
    /// disabled. `unsolicited` is always 0 (an HTTP/3 response belongs to its
    /// own request stream).
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        self.pool
            .as_ref()
            .map_or_else(PoolStats::default, Doh3Pool::stats)
    }
}

/// Builds the RFC 8484 request for `query` against `uri` in `method`'s wire
/// format.
fn build_doh_request(
    uri: &Uri,
    method: DohMethod,
    query: &Message,
) -> Result<Request<Full<Bytes>>> {
    let payload = query.encode()?;

    match method {
        DohMethod::Post => Request::builder()
            .method("POST")
            .uri(uri.clone())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|err| Error::Transport(err.to_string())),
        DohMethod::Get => {
            let encoded = URL_SAFE_NO_PAD.encode(&payload);
            let mut parts = uri.clone().into_parts();
            let path = parts
                .path_and_query
                .as_ref()
                .map(|pq| pq.path())
                .unwrap_or("/");
            let separator = if path.contains('?') { '&' } else { '?' };
            let path_and_query = format!("{path}{separator}dns={encoded}");
            parts.path_and_query = Some(
                http::uri::PathAndQuery::from_str(&path_and_query)
                    .map_err(|err| Error::Transport(err.to_string()))?,
            );
            let uri = Uri::from_parts(parts).map_err(|err| Error::Transport(err.to_string()))?;

            Request::builder()
                .method("GET")
                .uri(uri)
                .header("accept", "application/dns-message")
                .body(Full::new(Bytes::new()))
                .map_err(|err| Error::Transport(err.to_string()))
        }
    }
}

impl DohBackend {
    /// Builds a DoH backend from `config` with connection reuse on
    /// ([`PoolConfig::new`]).
    pub fn new(config: DohBackendConfig) -> Self {
        Self { config, pool: None }.with_pool(PoolConfig::new())
    }

    /// Replaces the connection-reuse policy. [`PoolConfig::disabled`] makes
    /// every query build its own HTTP client and connection, as before
    /// connection reuse existed.
    ///
    /// `max_connections x max_in_flight` bounds the queries in flight,
    /// `idle_timeout` closes idle connections and `max_lifetime` replaces the
    /// client (see the type documentation for how this applies to HTTP/2 and
    /// HTTP/1.1).
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.is_enabled().then(|| DohPool::new(pool, &self.config));
        self
    }

    /// A snapshot of the connection counters. All zeros when reuse is
    /// disabled.
    ///
    /// The HTTP client owns the connections, so the counters come from a
    /// wrapper around its connector and from the admission step:
    /// `connections_open` and `connections_opened` count TLS connections that
    /// were established (exactly), `queries`, `in_flight`, `queued` and
    /// `retries` count calls, and `reused_queries` counts responses that came
    /// over a connection that had already answered a query. `closed_lifetime`
    /// counts connections that closed after their client was replaced for
    /// reaching the maximum lifetime. The client does not say why it closed
    /// any other connection, so `closed_idle` and `closed_error` are always 0
    /// (`connections_opened - connections_open` is the number of closed
    /// connections) and `unsolicited` is 0 because HTTP correlates answers
    /// with requests.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        self.pool
            .as_ref()
            .map_or_else(PoolStats::default, DohPool::stats)
    }

    /// The per-query path of a backend with reuse disabled: a new client,
    /// and so a new connection, for every call.
    async fn resolve_unpooled(&self, query: &Message) -> Result<Message> {
        let https = HttpsConnectorBuilder::new()
            .with_tls_config((*self.config.tls_config).clone())
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);

        let request = build_doh_request(&self.config.uri, self.config.method, query)?;

        let response = timeout(self.config.timeout, client.request(request))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(map_hyper_error)?;

        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "doh server returned http status {}",
                response.status()
            )));
        }

        let body = timeout(self.config.timeout, response.into_body().collect())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?
            .to_bytes();

        decode_validated(query, &body)
    }
}

#[async_trait]
impl UpstreamBackend for DohBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        match &self.pool {
            Some(pool) => pool.resolve(&self.config, query).await,
            None => self.resolve_unpooled(query).await,
        }
    }
}

#[async_trait]
impl UpstreamBackend for Doh3Backend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        if self.config.uri.host().is_none() {
            return Err(Error::Transport("DoH HTTP/3 URI has no host".to_string()));
        }
        match &self.pool {
            Some(pool) => pool.query(query).await,
            None => self.resolve_unpooled(query).await,
        }
    }
}

impl Doh3Backend {
    /// The per-query path of a backend with reuse disabled: one endpoint, one
    /// connection and one request for every call.
    async fn resolve_unpooled(&self, query: &Message) -> Result<Message> {
        let host = self
            .config
            .uri
            .host()
            .ok_or_else(|| Error::Transport("DoH HTTP/3 URI has no host".to_string()))?;
        let client_config = QuicClientConfig::try_from(Arc::clone(&self.tls_config))
            .map_err(|err| Error::Tls(err.to_string()))?;
        let mut quinn_config = QuinnClientConfig::new(Arc::new(client_config));
        quinn_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let endpoint = Endpoint::client(match self.config.server {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        })
        .map_err(|err| Error::Transport(err.to_string()))?;
        let connecting = endpoint
            .connect_with(quinn_config, self.config.server, host)
            .map_err(|err| Error::Transport(err.to_string()))?;
        let connection = timeout(self.config.timeout, connecting)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(map_quinn_connection_error)?;
        if connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol)
            .as_deref()
            != Some(b"h3")
        {
            return Err(Error::Tls(
                "HTTP/3 peer did not negotiate ALPN h3".to_string(),
            ));
        }

        let (mut driver, mut sender) = timeout(
            self.config.timeout,
            h3::client::new(h3_quinn::Connection::new(connection)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
        let driver_task = tokio::spawn(async move { driver.wait_idle().await });
        let request = build_doh_request(&self.config.uri, self.config.method, query)?;
        let (parts, body) = request.into_parts();
        let mut stream = timeout(
            self.config.timeout,
            sender.send_request(http::Request::from_parts(parts, ())),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
        let bytes = body.into_inner().unwrap_or_default();
        if !bytes.is_empty() {
            timeout(self.config.timeout, stream.send_data(bytes))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|err| Error::Transport(err.to_string()))?;
        }
        timeout(self.config.timeout, stream.finish())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?;
        let response = timeout(self.config.timeout, stream.recv_response())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "doh HTTP/3 server returned http status {}",
                response.status()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = timeout(self.config.timeout, stream.recv_data())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?
        {
            body.extend_from_slice(chunk.chunk());
        }
        endpoint.close(0u32.into(), b"request complete");
        driver_task.abort();
        decode_validated(query, &body)
    }
}

/// The application error code a pooled HTTP/3 connection is closed with:
/// `H3_NO_ERROR` (RFC 9114 §8.1).
const H3_NO_ERROR: u32 = 0x100;

/// The largest DNS message a response body may carry.
const MAX_DNS_BODY: usize = 65_535;

/// Opens the HTTP/3 connections of one [`Doh3Backend`] pool.
struct Doh3Connector {
    client: QuicClient,
    /// Bounds the HTTP/3 setup that follows the QUIC handshake.
    timeout: Duration,
}

/// One pooled HTTP/3 connection.
struct Doh3Conn {
    connection: quinn::Connection,
    /// The cloneable request sender; cloned per query under the lock, which
    /// is never held across an await.
    sender: Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    /// The HTTP/3 driver task (control stream, `GOAWAY`); it ends when the
    /// connection does.
    driver: AbortOnDrop,
    /// The runtime that opened it; a connection whose runtime is gone has lost
    /// its driver tasks and can never carry another query.
    runtime: Option<RuntimeId>,
    /// The connection has answered at least one query.
    answered: AtomicBool,
}

impl Connector for Doh3Connector {
    type Conn = Doh3Conn;

    async fn connect(&self, _hooks: PoolHooks) -> Result<Doh3Conn> {
        let connection = self.client.connect().await?;
        if connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.protocol)
            .as_deref()
            != Some(b"h3")
        {
            connection.close(quinn::VarInt::from_u32(NO_ERROR), b"");
            return Err(Error::Tls(
                "HTTP/3 peer did not negotiate ALPN h3".to_string(),
            ));
        }
        let (mut driver, sender) = timeout(
            self.timeout,
            h3::client::new(h3_quinn::Connection::new(connection.clone())),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
        let task = tokio::spawn(async move { driver.wait_idle().await });
        Ok(Doh3Conn {
            connection,
            sender: Mutex::new(sender),
            driver: AbortOnDrop::new(task.abort_handle()),
            runtime: QuicClient::current_runtime(),
            answered: AtomicBool::new(false),
        })
    }

    fn is_alive(&self, conn: &Doh3Conn) -> bool {
        conn.connection.close_reason().is_none()
            && !conn.driver.is_finished()
            && QuicClient::current_runtime()
                .is_none_or(|now| conn.runtime.is_none_or(|opened| opened == now))
    }

    fn close(&self, conn: &Doh3Conn) {
        conn.connection
            .close(quinn::VarInt::from_u32(H3_NO_ERROR), &[]);
    }
}

/// A failed attempt and the facts the retry rule needs.
struct H3Failure {
    error: Error,
    /// The failure closed the connection (or the HTTP/3 layer reported a
    /// connection-level error), as opposed to failing one request.
    closed: bool,
    /// The connection had already answered a query when the failure was
    /// noticed.
    answered: bool,
}

impl H3Failure {
    /// A failure that says nothing about a stale pooled connection.
    fn local(error: Error) -> Self {
        H3Failure {
            error,
            closed: false,
            answered: false,
        }
    }
}

/// Whether a failed attempt is sent once more on a fresh connection: the
/// connection was closed after it had answered a query (so a stale pooled
/// connection is plausible), the opcode is `QUERY`, this attempt was not
/// itself the retry, the error is not a timeout or a TLS error, and the
/// call's deadline has not passed.
fn retry_allowed(
    failed: &H3Failure,
    is_query: bool,
    fresh: bool,
    now: Instant,
    deadline: Instant,
) -> bool {
    failed.closed
        && failed.answered
        && is_query
        && !fresh
        && !matches!(failed.error, Error::Timeout | Error::Tls(_))
        && now < deadline
}

/// A failure inside one request exchange.
struct Exchange {
    error: Error,
    connection_level: bool,
}

impl Exchange {
    fn local(error: Error) -> Self {
        Exchange {
            error,
            connection_level: false,
        }
    }

    fn from_stream(err: H3StreamError) -> Self {
        Exchange {
            // A connection error, or a `GOAWAY` (the server will not take
            // more requests on this connection), says the connection is
            // unusable; a reset or a refusal of one stream does not.
            connection_level: matches!(
                err,
                H3StreamError::ConnectionError { .. } | H3StreamError::RemoteClosing { .. }
            ),
            error: Error::Transport(err.to_string()),
        }
    }
}

type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Cancels a request unless it was read to its end, so a cancelled, timed out
/// or failed query frees its stream: the request is reset and the response
/// side told to stop, both with `H3_REQUEST_CANCELLED` (RFC 9114 §4.1.1).
///
/// `h3-quinn` cannot stop the response side while a read of it is in flight
/// (the QUIC stream is inside the pending read and asking it to stop panics),
/// which is exactly the state of a call dropped while it waits for the answer.
/// In that case only the request side is reset here and dropping the stream
/// makes the QUIC layer stop the response side with error code 0.
struct CancelOnDrop {
    stream: H3RequestStream,
    done: bool,
    /// A read of the response may be in flight (set around each read).
    reading: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if !self.done {
            self.stream.stop_stream(H3Code::H3_REQUEST_CANCELLED);
            if !self.reading {
                self.stream.stop_sending(H3Code::H3_REQUEST_CANCELLED);
            }
        }
    }
}

/// The pooled client of one HTTP/3 DoH upstream.
struct Doh3Pool {
    pool: Pool<Doh3Connector>,
    uri: Uri,
    method: DohMethod,
    /// Bounds a whole call: capacity wait, connection setup, the request and
    /// the response, retry included.
    timeout: Duration,
}

impl Doh3Pool {
    /// The pool's counters, after retiring connections that have died.
    fn stats(&self) -> PoolStats {
        self.pool.sweep();
        self.pool.stats()
    }

    /// Sends `query` on a pooled connection and returns the answer, with the
    /// caller's message id restored.
    async fn query(&self, query: &Message) -> Result<Message> {
        let now = Instant::now();
        let deadline = now
            .checked_add(self.timeout)
            .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365));
        let is_query = matches!(query.header.opcode, Opcode::Query);
        let mut fresh = false;
        loop {
            match self.attempt(query, deadline, fresh).await {
                Ok(answer) => return Ok(answer),
                Err(failed) => {
                    if retry_allowed(&failed, is_query, fresh, Instant::now(), deadline) {
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
        query: &Message,
        deadline: Instant,
        fresh: bool,
    ) -> std::result::Result<Message, H3Failure> {
        let (parts, body) = build_doh_request(&self.uri, self.method, query)
            .map_err(H3Failure::local)?
            .into_parts();
        let body = body.into_inner().unwrap_or_default();
        let lease = if fresh {
            self.pool.acquire_fresh(deadline).await
        } else {
            self.pool.acquire(deadline).await
        }
        .map_err(H3Failure::local)?;
        let conn = Arc::clone(lease.conn());
        let mut sender = conn
            .sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        // The failure of one request leaves the connection alone. Only a
        // failure that closed the connection retires it, and only a
        // connection that had answered before (so the failure may be a stale
        // pooled connection) justifies sending a safe query again.
        let failed = |error: Error, connection_level: bool| {
            let closed = connection_level || conn.connection.close_reason().is_some();
            if closed {
                lease.mark_dead();
            }
            H3Failure {
                error,
                closed,
                answered: conn.answered.load(Ordering::Relaxed),
            }
        };

        // Dropping this future (the caller gave up, or the deadline passed)
        // drops the guard, which cancels the request.
        let exchanged = timeout_at(deadline, async {
            let stream = sender
                .send_request(Request::from_parts(parts, ()))
                .await
                .map_err(Exchange::from_stream)?;
            let mut guard = CancelOnDrop {
                stream,
                done: false,
                reading: false,
            };
            if !body.is_empty() {
                guard
                    .stream
                    .send_data(body)
                    .await
                    .map_err(Exchange::from_stream)?;
            }
            guard.stream.finish().await.map_err(Exchange::from_stream)?;
            guard.reading = true;
            let response = guard.stream.recv_response().await;
            guard.reading = false;
            let response = response.map_err(Exchange::from_stream)?;
            if !response.status().is_success() {
                return Err(Exchange::local(Error::Transport(format!(
                    "doh HTTP/3 server returned http status {}",
                    response.status()
                ))));
            }
            let mut data = Vec::new();
            loop {
                guard.reading = true;
                let next = guard.stream.recv_data().await;
                guard.reading = false;
                let Some(mut chunk) = next.map_err(Exchange::from_stream)? else {
                    break;
                };
                if data.len().saturating_add(chunk.remaining()) > MAX_DNS_BODY {
                    return Err(Exchange::local(Error::Transport(
                        "doh HTTP/3 response body is larger than a DNS message".to_string(),
                    )));
                }
                data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            // The response was read to its end: nothing is left to cancel.
            guard.done = true;
            decode_validated(query, &data).map_err(Exchange::local)
        })
        .await;
        match exchanged {
            Err(_) => {
                lease.note_timeout();
                Err(H3Failure::local(Error::Timeout))
            }
            Ok(Err(exchange)) => Err(failed(exchange.error, exchange.connection_level)),
            Ok(Ok(answer)) => {
                conn.answered.store(true, Ordering::Relaxed);
                lease.complete();
                Ok(answer)
            }
        }
    }
}

/// Interval of the HTTP/2 keep-alive pings sent while a stream is open.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// Longest wait for the answer to an HTTP/2 keep-alive ping.
const H2_KEEP_ALIVE_TIMEOUT_MAX: Duration = Duration::from_secs(20);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// The long-lived HTTP client of a pooled [`DohBackend`].
type DohClient = Client<CountingConnector, Full<Bytes>>;

/// Relaxed atomic counters behind [`DohBackend::pool_stats`].
#[derive(Debug, Default)]
struct DohCounters {
    open: AtomicU64,
    opened: AtomicU64,
    closed_lifetime: AtomicU64,
    in_flight: AtomicU64,
    queries: AtomicU64,
    reused_queries: AtomicU64,
    retries: AtomicU64,
    queued: AtomicU64,
}

impl DohCounters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn drop_one(counter: &AtomicU64) {
        // Saturating at zero keeps a bookkeeping bug from wrapping a gauge to
        // `u64::MAX`.
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    fn snapshot(&self) -> PoolStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        PoolStats {
            connections_open: get(&self.open),
            connections_opened: get(&self.opened),
            closed_idle: 0,
            closed_lifetime: get(&self.closed_lifetime),
            closed_error: 0,
            in_flight: get(&self.in_flight),
            queries: get(&self.queries),
            reused_queries: get(&self.reused_queries),
            retries: get(&self.retries),
            queued: get(&self.queued),
            unsolicited: 0,
        }
    }
}

/// Per-connection marker the connector attaches to every response (and every
/// client error) of its connection. It records whether the connection has
/// already answered a query, which is the "reused connection" test of the
/// retry rule.
#[derive(Clone)]
struct ConnToken(Arc<AtomicBool>);

impl ConnToken {
    /// Whether the connection has answered a query.
    fn answered(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Marks the connection as having answered a query and returns whether it
    /// had already answered one.
    fn mark_answered(&self) -> bool {
        self.0.swap(true, Ordering::AcqRel)
    }
}

/// State shared by one client generation, its connector, its connections and
/// the calls that use it.
///
/// It exists for the cold start: the HTTP client cannot know whether the
/// server speaks HTTP/2 until the first TLS handshake has negotiated ALPN, so
/// a burst of queries that finds no connection would open one connection per
/// query and drop all but one once ALPN picks HTTP/2. The `gate` lets one
/// call at a time start a connection while the generation has none; the
/// others wait for it and then multiplex over the connection it opened. When
/// the first connection turns out to be HTTP/1.1 the gate opens at once, so
/// the waiting calls open the connections they need in parallel.
struct GenState {
    /// Set when the generation is replaced for reaching the maximum lifetime.
    retired: AtomicBool,
    /// Connections of this generation that are currently open.
    open: AtomicU64,
    /// Set when a connection of this generation negotiated HTTP/1.1.
    http1: AtomicBool,
    /// Notified when `http1` is set.
    http1_seen: Notify,
    gate: tokio::sync::Mutex<()>,
}

impl GenState {
    fn new() -> Self {
        GenState {
            retired: AtomicBool::new(false),
            open: AtomicU64::new(0),
            http1: AtomicBool::new(false),
            http1_seen: Notify::new(),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    fn has_connection(&self) -> bool {
        self.open.load(Ordering::Acquire) > 0
    }

    /// Resolves once a connection of this generation negotiated HTTP/1.1.
    async fn wait_for_http1(&self) {
        loop {
            let seen = self.http1_seen.notified();
            tokio::pin!(seen);
            // Registering before the check cannot miss a connection that is
            // established in between.
            seen.as_mut().enable();
            if self.http1.load(Ordering::Acquire) {
                return;
            }
            seen.await;
        }
    }

    /// Runs `request` against this generation until `deadline`. While the
    /// generation has no connection only one call at a time runs its request
    /// (see the type documentation); it lets go when its response arrives or
    /// when the connection it opened turns out to be HTTP/1.1.
    async fn send<F: Future>(
        &self,
        deadline: Instant,
        request: F,
    ) -> std::result::Result<F::Output, Error> {
        let guard = if self.has_connection() {
            None
        } else {
            let guard = timeout_at(deadline, self.gate.lock())
                .await
                .map_err(|_| Error::Timeout)?;
            // A call ahead of this one may have connected while it waited.
            (!self.has_connection()).then_some(guard)
        };
        timeout_at(deadline, async {
            tokio::pin!(request);
            if let Some(guard) = guard {
                tokio::select! {
                    output = &mut request => return output,
                    () = self.wait_for_http1() => drop(guard),
                }
            }
            request.await
        })
        .await
        .map_err(|_| Error::Timeout)
    }
}

/// A connection handed to the HTTP client. It counts itself in
/// [`DohCounters`] while it is alive and carries a [`ConnToken`].
struct CountedIo {
    io: MaybeHttpsStream<TokioIo<TcpStream>>,
    token: Arc<AtomicBool>,
    counters: Arc<DohCounters>,
    generation: Arc<GenState>,
}

impl CountedIo {
    fn new(
        io: MaybeHttpsStream<TokioIo<TcpStream>>,
        counters: Arc<DohCounters>,
        generation: Arc<GenState>,
    ) -> Self {
        DohCounters::bump(&counters.open);
        DohCounters::bump(&counters.opened);
        generation.open.fetch_add(1, Ordering::AcqRel);
        if !io.connected().is_negotiated_h2() {
            generation.http1.store(true, Ordering::Release);
            generation.http1_seen.notify_waiters();
        }
        CountedIo {
            io,
            token: Arc::new(AtomicBool::new(false)),
            counters,
            generation,
        }
    }
}

impl Drop for CountedIo {
    fn drop(&mut self) {
        DohCounters::drop_one(&self.counters.open);
        DohCounters::drop_one(&self.generation.open);
        if self.generation.retired.load(Ordering::Acquire) {
            DohCounters::bump(&self.counters.closed_lifetime);
        }
    }
}

impl Connection for CountedIo {
    fn connected(&self) -> Connected {
        self.io
            .connected()
            .extra(ConnToken(Arc::clone(&self.token)))
    }
}

impl hyper::rt::Read for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
}

/// The HTTPS connector of a pooled client: HTTP/1.1 and HTTP/2 over TLS, with
/// `TCP_NODELAY` set on every socket.
///
/// A pooled connection carries many small request and response frames, and
/// over HTTP/2 all queries share one connection; without `TCP_NODELAY` Nagle's
/// algorithm and delayed ACKs hold a frame back until the previous one is
/// acknowledged, which adds stalls of tens of milliseconds.
fn pooled_https_connector(tls_config: &Arc<ClientConfig>) -> HttpsConnector<HttpConnector> {
    let mut http = HttpConnector::new();
    // The TLS layer is what enforces `https`; the plain connector must accept
    // the `https` scheme it is asked to open a socket for.
    http.enforce_http(false);
    http.set_nodelay(true);
    HttpsConnectorBuilder::new()
        .with_tls_config((**tls_config).clone())
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http)
}

/// The HTTPS connector of one client generation, wrapped so the connections
/// it establishes are counted. It changes nothing about how connections are
/// made: the TLS configuration, SNI and ALPN are those of the inner
/// connector.
#[derive(Clone)]
struct CountingConnector {
    inner: HttpsConnector<HttpConnector>,
    counters: Arc<DohCounters>,
    generation: Arc<GenState>,
}

impl Service<Uri> for CountingConnector {
    type Response = CountedIo;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<CountedIo, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), BoxError>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let connecting = self.inner.call(dst);
        let counters = Arc::clone(&self.counters);
        let generation = Arc::clone(&self.generation);
        Box::pin(async move { Ok(CountedIo::new(connecting.await?, counters, generation)) })
    }
}

/// One HTTP client and the state its connections and calls share.
struct Generation {
    client: DohClient,
    state: Arc<GenState>,
}

/// The current generation and when it was created.
struct Current {
    generation: Arc<Generation>,
    since: std::time::Instant,
}

/// A call's admission: the permit that bounds the queries in flight and the
/// in-flight gauge. Both are released when it is dropped, including when the
/// caller's future is cancelled.
struct Admission {
    counters: Arc<DohCounters>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for Admission {
    fn drop(&mut self) {
        DohCounters::drop_one(&self.counters.in_flight);
    }
}

/// Why one attempt failed and whether the retry rule allows another.
struct Failure {
    error: Error,
    retryable: bool,
}

impl Failure {
    fn fatal(error: Error) -> Self {
        Failure {
            error,
            retryable: false,
        }
    }
}

/// The connection-reuse state of a [`DohBackend`]: one long-lived HTTP client
/// (replaced when it reaches the maximum lifetime), the admission semaphore
/// and the counters.
struct DohPool {
    pool: PoolConfig,
    /// Fixed at construction: every client generation is built from it.
    tls_config: Arc<ClientConfig>,
    keep_alive_timeout: Duration,
    counters: Arc<DohCounters>,
    admission: Arc<Semaphore>,
    /// Held only to clone the current generation or replace it; never across
    /// an `.await`.
    current: Mutex<Current>,
}

impl DohPool {
    fn new(pool: PoolConfig, config: &DohBackendConfig) -> Self {
        let counters = Arc::new(DohCounters::default());
        let keep_alive_timeout = config
            .timeout
            .clamp(Duration::from_secs(1), H2_KEEP_ALIVE_TIMEOUT_MAX);
        let admission = Arc::new(Semaphore::new(pool.capacity()));
        let tls_config = Arc::clone(&config.tls_config);
        let first = Self::build_generation(&tls_config, &pool, keep_alive_timeout, &counters);
        DohPool {
            pool,
            tls_config,
            keep_alive_timeout,
            counters,
            admission,
            current: Mutex::new(Current {
                generation: first,
                since: std::time::Instant::now(),
            }),
        }
    }

    /// Builds a client with the pool's idle timeout, bound and keep-alive.
    fn build_generation(
        tls_config: &Arc<ClientConfig>,
        pool: &PoolConfig,
        keep_alive_timeout: Duration,
        counters: &Arc<DohCounters>,
    ) -> Arc<Generation> {
        let state = Arc::new(GenState::new());
        let https = pooled_https_connector(tls_config);
        let connector = CountingConnector {
            inner: https,
            counters: Arc::clone(counters),
            generation: Arc::clone(&state),
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(pool.idle_timeout_value())
            .pool_max_idle_per_host(pool.capacity())
            .http2_keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
            .http2_keep_alive_timeout(keep_alive_timeout);
        Arc::new(Generation {
            client: builder.build(connector),
            state,
        })
    }

    fn stats(&self) -> PoolStats {
        self.counters.snapshot()
    }

    /// The generation new queries use, replacing it first when it reached the
    /// maximum lifetime. The old one is marked retired and dropped here; it
    /// stays alive only while queries that already hold it are in flight.
    fn generation(&self) -> Arc<Generation> {
        let (generation, old) = {
            let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
            let expired = self
                .pool
                .max_lifetime_value()
                .is_some_and(|max| current.since.elapsed() >= max);
            let old = if expired {
                let fresh = Self::build_generation(
                    &self.tls_config,
                    &self.pool,
                    self.keep_alive_timeout,
                    &self.counters,
                );
                current
                    .generation
                    .state
                    .retired
                    .store(true, Ordering::Release);
                current.since = std::time::Instant::now();
                Some(std::mem::replace(&mut current.generation, fresh))
            } else {
                None
            };
            (Arc::clone(&current.generation), old)
        };
        drop(old);
        generation
    }

    /// Waits for room for one more query, in arrival order, until `deadline`.
    async fn admit(&self, deadline: Instant) -> Result<Admission> {
        let closed = || Error::Transport("doh connection pool closed".to_string());
        let permit = match Arc::clone(&self.admission).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                DohCounters::bump(&self.counters.queued);
                timeout_at(deadline, Arc::clone(&self.admission).acquire_owned())
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(|_| closed())?
            }
            Err(TryAcquireError::Closed) => return Err(closed()),
        };
        DohCounters::bump(&self.counters.queries);
        DohCounters::bump(&self.counters.in_flight);
        Ok(Admission {
            counters: Arc::clone(&self.counters),
            _permit: permit,
        })
    }

    async fn resolve(&self, config: &DohBackendConfig, query: &Message) -> Result<Message> {
        let now = Instant::now();
        let deadline = now
            .checked_add(config.timeout)
            .unwrap_or_else(|| now + Duration::from_secs(365 * 24 * 60 * 60));
        let _admission = self.admit(deadline).await?;
        let mut retried = false;
        loop {
            let generation = self.generation();
            match self.attempt(&generation, config, query, deadline).await {
                Ok(answer) => return Ok(answer),
                Err(failure)
                    if failure.retryable
                        && !retried
                        && matches!(query.header.opcode, Opcode::Query)
                        && Instant::now() < deadline =>
                {
                    retried = true;
                    DohCounters::bump(&self.counters.retries);
                }
                Err(failure) => return Err(failure.error),
            }
        }
    }

    /// One request and response exchange on the pooled client.
    async fn attempt(
        &self,
        generation: &Generation,
        config: &DohBackendConfig,
        query: &Message,
        deadline: Instant,
    ) -> std::result::Result<Message, Failure> {
        let request =
            build_doh_request(&config.uri, config.method, query).map_err(Failure::fatal)?;
        let sent = generation
            .state
            .send(deadline, generation.client.request(request))
            .await
            .map_err(Failure::fatal)?;
        let response = match sent {
            Err(err) => {
                let retryable = failed_on_answering_connection(&err);
                return Err(Failure {
                    error: map_hyper_error(err),
                    retryable,
                });
            }
            Ok(response) => response,
        };

        // Whether this connection had already answered a query before this
        // response; a failure while reading the body is then a stale-pool
        // artefact the retry rule may repair.
        let reused = response
            .extensions()
            .get::<ConnToken>()
            .is_some_and(ConnToken::mark_answered);
        if reused {
            DohCounters::bump(&self.counters.reused_queries);
        }

        if !response.status().is_success() {
            return Err(Failure::fatal(Error::Transport(format!(
                "doh server returned http status {}",
                response.status()
            ))));
        }

        let body = match timeout_at(deadline, response.into_body().collect()).await {
            Err(_) => return Err(Failure::fatal(Error::Timeout)),
            Ok(Err(err)) => {
                return Err(Failure {
                    retryable: reused && is_connection_level(&err),
                    error: Error::Transport(err.to_string()),
                });
            }
            Ok(Ok(collected)) => collected.to_bytes(),
        };

        decode_validated(query, &body).map_err(Failure::fatal)
    }
}

/// Whether a failed request broke on a connection that had already answered
/// a query: the request was handed to an established, reused connection and
/// the connection failed (closed, reset, `GOAWAY`), as opposed to a failed
/// connect, a TLS error, or a protocol or user error.
fn failed_on_answering_connection(err: &hyper_util::client::legacy::Error) -> bool {
    let answered = err.connect_info().is_some_and(|connected| {
        let mut extensions = http::Extensions::new();
        connected.get_extras(&mut extensions);
        extensions
            .get::<ConnToken>()
            .is_some_and(ConnToken::answered)
    });
    answered && !err.is_connect() && !error_chain_is_tls(err) && is_connection_level(err)
}

/// Whether `err` is a failure of the connection rather than of the message:
/// a malformed message or a misuse of the client is not.
fn is_connection_level(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if let Some(hyper_err) = node.downcast_ref::<hyper::Error>()
            && (hyper_err.is_parse()
                || hyper_err.is_parse_too_large()
                || hyper_err.is_parse_status()
                || hyper_err.is_user())
        {
            return false;
        }
        current = node.source();
    }
    true
}

/// Decodes a DoH response body and checks it against `query` with
/// [`validate_response`]. The message id is not compared: RFC 8484 §4.1
/// has DoH clients use id 0 and the HTTP exchange itself pairs the request
/// with its response, so a conforming server may answer with an id that
/// differs from the caller's query id. The returned response carries the
/// caller's query id, so it can be relayed to the original client as is.
fn decode_validated(query: &Message, body: &[u8]) -> Result<Message> {
    let mut response = Message::decode(body)?;
    validate_response(query, &response, IdCheck::Ignore)?;
    response.header.id = query.header.id;
    Ok(response)
}

/// Maps QUIC handshake failures onto the crate's stable error boundary.
/// QUIC represents TLS alerts as transport errors in the `0x100..0x200`
/// range (RFC 9000 §20.1), so they remain TLS failures to callers rather
/// than being flattened into generic transport errors.
fn map_quinn_connection_error(err: quinn::ConnectionError) -> Error {
    if let quinn::ConnectionError::TransportError(transport) = &err
        && (0x100..0x200).contains(&u64::from(transport.code))
    {
        return Error::Tls(err.to_string());
    }
    Error::Transport(err.to_string())
}

/// Maps a `hyper_util` client error to [`Error::Tls`] if it stemmed from
/// the TLS layer, or [`Error::Transport`] otherwise. The HTTP client
/// crate's error taxonomy determines which category a given failure falls
/// into.
fn map_hyper_error<E: std::error::Error + 'static>(err: E) -> Error {
    if error_chain_is_tls(&err) {
        Error::Tls(err.to_string())
    } else {
        Error::Transport(err.to_string())
    }
}

/// Walks `err`'s `source()` chain, additionally descending into any
/// `std::io::Error` node's own inner boxed error (which `io::Error` does
/// not expose via `Error::source()`), looking for a `rustls::Error`
/// (`hyper-rustls` reports TLS handshake/certificate failures as an
/// `io::Error` wrapping a `rustls::Error`, not as a `rustls::Error`
/// directly reachable via `source()`).
fn error_chain_is_tls(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(node) = current {
        if node.downcast_ref::<rustls::Error>().is_some() {
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
    use hyper::body::Incoming;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use quinn::ServerConfig as QuinnServerConfig;
    use quinn::crypto::rustls::QuicServerConfig;
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

    fn self_signed_fixture() -> (ServerConfig, ClientConfig) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        (server_config, client_config)
    }

    fn http3_fixture() -> (QuinnServerConfig, ClientConfig) {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = QuicServerConfig::try_from(Arc::new(server_config)).unwrap();
        (
            QuinnServerConfig::with_crypto(Arc::new(crypto)),
            client_config,
        )
    }

    async fn serve_one_doh3_response(
        endpoint: quinn::Endpoint,
        response: Message,
        expected_method: hyper::Method,
    ) {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let data = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(b"h3".as_slice()));
        let mut h3_connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.method(), expected_method);
        assert_eq!(request.uri().path(), "/dns-query");
        while stream.recv_data().await.unwrap().is_some() {}
        stream
            .send_response(
                http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(Bytes::from(response.encode().unwrap()))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Keep the H3 connection alive until the client finishes reading;
        // dropping it immediately sends H3_NO_ERROR before the response can
        // deterministically reach the loopback client.
        let _ = h3_connection.accept().await;
    }

    async fn serve_one_doh3_status(endpoint: quinn::Endpoint, status: http::StatusCode) {
        let incoming = endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let mut h3_connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = h3_connection.accept().await.unwrap().unwrap();
        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
        while stream.recv_data().await.unwrap().is_some() {}
        stream
            .send_response(http::Response::builder().status(status).body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = h3_connection.accept().await;
    }

    /// Minimal, single-request, loopback-only HTTP/1.1-over-TLS responder:
    /// reads one HTTP request off the TLS stream (headers-only, i.e. GET,
    /// or with a `content-length` body for POST) and writes back a fixed
    /// `application/dns-message` 200 response carrying `response`. Fully
    /// offline/deterministic per `@.claude/rules/ci.md` — no real network
    /// I/O, no external HTTP crate on the server side.
    async fn serve_one_doh_response(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        response: Message,
    ) {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let n = tls_stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before headers were complete");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_length: usize = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        while buf.len() < header_end + content_length {
            let n = tls_stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before body was complete");
            buf.extend_from_slice(&chunk[..n]);
        }

        let bytes = response.encode().unwrap();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            bytes.len()
        );
        tls_stream
            .write_all(http_response.as_bytes())
            .await
            .unwrap();
        tls_stream.write_all(&bytes).await.unwrap();
        tls_stream.shutdown().await.unwrap();
    }

    /// Serves one TLS-ALPN-negotiated HTTP/2 DoH request. The assertion on
    /// the selected ALPN protocol makes this an end-to-end HTTP/2 test, not
    /// merely a server-side HTTP/2 parser test.
    async fn serve_one_doh_h2_response(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        response: Message,
        expected_method: hyper::Method,
    ) {
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let tls_stream = acceptor.accept(tcp_stream).await.unwrap();
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );

        let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
            let response = response.clone();
            let expected_method = expected_method.clone();
            async move {
                assert_eq!(request.version(), hyper::Version::HTTP_2);
                assert_eq!(request.method(), expected_method);
                assert_eq!(request.uri().path(), "/dns-query");
                let _ = request.into_body().collect().await.unwrap();
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/dns-message")
                        .body(Full::new(Bytes::from(response.encode().unwrap())))
                        .unwrap(),
                )
            }
        });

        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(tls_stream), service)
            .await
            .unwrap();
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_get_against_a_loopback_https_server() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_answer = answer_for("example.com", 0);
        let responder = tokio::spawn(serve_one_doh_response(listener, acceptor, expected_answer));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("doh backend resolves over get");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_post_against_a_loopback_https_server() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_answer = answer_for("example.com", 0);
        let responder = tokio::spawn(serve_one_doh_response(listener, acceptor, expected_answer));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("doh backend resolves over post");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_get_over_http2() {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh_h2_response(
            listener,
            acceptor,
            answer_for("example.com", 0),
            hyper::Method::GET,
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        // The backend keeps its HTTP/2 connection open for later queries, and
        // this responder serves until the connection ends: dropping the
        // backend closes it.
        drop(backend);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_resolves_with_post_over_http2() {
        let (mut server_config, client_config) = self_signed_fixture();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh_h2_response(
            listener,
            acceptor,
            answer_for("example.com", 0),
            hyper::Method::POST,
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        // See the GET variant: the pooled connection must be closed for the
        // single-connection responder to finish.
        drop(backend);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_resolves_with_get_over_http3() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_response(
            endpoint,
            answer_for("example.com", 0),
            hyper::Method::GET,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });
        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_rejects_a_response_with_qr_zero() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let mut reflected = answer_for("example.com", 0);
        reflected.header.qr = false;
        let responder = tokio::spawn(serve_one_doh3_response(
            endpoint,
            reflected,
            hyper::Method::GET,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });
        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a DoH3 response with QR=0 is rejected");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_rejects_a_response_for_a_different_question() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(serve_one_doh_response(
            listener,
            acceptor,
            answer_for("example.org", 0),
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a DoH response for another question is rejected");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_accepts_id_zero_and_a_case_different_name() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(serve_one_doh_response(
            listener,
            acceptor,
            answer_for("EXAMPLE.COM", 0),
        ));

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("RFC 8484 id 0 and a case-different name are accepted");
        // The caller's query id is restored on the returned response.
        assert_eq!(answer.header.id, query_for("example.com").header.id);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_resolves_with_post_over_http3() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_response(
            endpoint,
            answer_for("example.com", 0),
            hyper::Method::POST,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Post,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });
        let answer = backend.resolve(&query_for("example.com")).await.unwrap();
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_transport_error_on_non_success_status() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_doh3_status(
            endpoint,
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ));
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a non-2xx HTTP/3 status is a transport failure");
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_tls_error_on_untrusted_certificate() {
        let (server_config, _trusted_client_config) = http3_fixture();
        let (_other_server_config, untrusted_client_config) = self_signed_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let _ = incoming.await;
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(untrusted_client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("an untrusted HTTP/3 certificate fails TLS");
        assert!(matches!(err, Error::Tls(_)), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_times_out_when_server_never_completes_handshake() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            // Keeping the endpoint alive without polling `accept` prevents a
            // server handshake while retaining a deterministic local UDP peer.
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(endpoint);
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_millis(30),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("an incomplete HTTP/3 handshake must time out");
        assert!(matches!(err, Error::Timeout), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh3_backend_returns_transport_when_peer_closes_after_handshake() {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            connection.close(0u32.into(), b"test peer closed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            server: addr,
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer closing a negotiated HTTP/3 connection is transport failure");
        assert!(matches!(err, Error::Transport(_)), "got {err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_returns_tls_error_on_untrusted_certificate() {
        let (server_config, _matching_client_config) = self_signed_fixture();
        let (_other_server_config, untrusting_client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp_stream).await;
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(untrusting_client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("untrusted certificate fails the tls handshake");
        assert!(
            matches!(err, Error::Tls(_)),
            "expected Tls error, got {err:?}"
        );
        let _ = responder.await;
    }

    #[tokio::test]
    async fn doh_backend_transport_error_on_non_success_status() {
        let (server_config, client_config) = self_signed_fixture();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = acceptor.accept(tcp_stream).await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = tls_stream.read(&mut buf).await.unwrap();
            let response = b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            tls_stream.write_all(response).await.unwrap();
            tls_stream.shutdown().await.unwrap();
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://localhost:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a non-2xx status is a transport-level failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn doh_backend_returns_transport_when_peer_closes_before_tls() {
        let (_server_config, client_config) = self_signed_fixture();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let backend = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!("https://127.0.0.1:{}/dns-query", addr.port())).unwrap(),
            method: DohMethod::Get,
            tls_config: Arc::new(client_config),
            timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer that closes before TLS is a transport failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }

    // ----- pooled client: a scripted loopback DoH server -----

    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::watch;
    use tokio::task::JoinSet;

    type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;
    type Handler = Arc<dyn Fn(Ctx) -> BoxFut<Action> + Send + Sync>;

    #[derive(Clone, Copy)]
    enum Proto {
        H1,
        H2,
    }

    /// What the scripted server knows about one request.
    struct Ctx {
        query: Message,
        /// Index of the accepted connection (0 for the first).
        conn: usize,
        /// Index of the request on its connection (0 for the first).
        nth: usize,
    }

    /// What the scripted server does with one request.
    enum Action {
        Reply(Message),
        /// Replies, then starts a graceful shutdown (`GOAWAY`) of the
        /// connection.
        ReplyThenGoaway(Message),
        Status(u16),
        /// A 200 response whose body is not a DNS message.
        Garbage,
        /// Drops the connection without answering.
        Hangup,
        /// Waits for a permit of the semaphore, then replies.
        Hold(Arc<Semaphore>, Message),
    }

    fn handler<F, Fut>(f: F) -> Handler
    where
        F: Fn(Ctx) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Action> + Send + 'static,
    {
        Arc::new(move |ctx| Box::pin(f(ctx)))
    }

    fn reply_to(query: &Message) -> Message {
        let mut reply = query.clone();
        reply.header.id = 0;
        reply.header.qr = true;
        reply
    }

    /// A handler that answers every query with its own question.
    fn echo() -> Handler {
        handler(|ctx| async move { Action::Reply(reply_to(&ctx.query)) })
    }

    struct ServerState {
        handler: Handler,
        accepts: AtomicUsize,
        live: AtomicUsize,
        requests: AtomicUsize,
        active: AtomicUsize,
        peak: AtomicUsize,
        order: Mutex<Vec<String>>,
        kill: watch::Sender<()>,
    }

    struct LiveGuard(Arc<ServerState>);

    impl Drop for LiveGuard {
        fn drop(&mut self) {
            self.0.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct TestServer {
        addr: std::net::SocketAddr,
        state: Arc<ServerState>,
        client: Arc<ClientConfig>,
        accept: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.accept.abort();
        }
    }

    async fn read_query(request: hyper::Request<Incoming>) -> Message {
        if request.method() == hyper::Method::GET {
            let encoded = request
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
                .expect("a GET request carries the dns parameter");
            Message::decode(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
        } else {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            Message::decode(&body).unwrap()
        }
    }

    fn dns_response(message: &Message) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/dns-message")
            .body(Full::new(Bytes::from(message.encode().unwrap())))
            .unwrap()
    }

    async fn handle_request(
        request: hyper::Request<Incoming>,
        state: Arc<ServerState>,
        hard: Arc<Notify>,
        goaway: Arc<Notify>,
        conn: usize,
        counter: Arc<AtomicUsize>,
    ) -> Response<Full<Bytes>> {
        let query = read_query(request).await;
        let nth = counter.fetch_add(1, Ordering::SeqCst);
        state.requests.fetch_add(1, Ordering::SeqCst);
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        state.peak.fetch_max(active, Ordering::SeqCst);
        state
            .order
            .lock()
            .unwrap()
            .push(query.questions[0].name.to_string());
        let action = (state.handler)(Ctx { query, conn, nth }).await;
        state.active.fetch_sub(1, Ordering::SeqCst);
        match action {
            Action::Reply(message) => dns_response(&message),
            Action::ReplyThenGoaway(message) => {
                goaway.notify_one();
                dns_response(&message)
            }
            Action::Status(code) => Response::builder()
                .status(code)
                .body(Full::new(Bytes::new()))
                .unwrap(),
            Action::Garbage => Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(&[0xde, 0xad])))
                .unwrap(),
            Action::Hangup => {
                hard.notify_one();
                std::future::pending().await
            }
            Action::Hold(permits, message) => {
                permits.acquire().await.unwrap().forget();
                dns_response(&message)
            }
        }
    }

    macro_rules! drive {
        ($conn:expr, $hard:ident, $goaway:ident, $kill:ident) => {{
            let conn = $conn;
            tokio::pin!(conn);
            loop {
                tokio::select! {
                    _ = conn.as_mut() => break,
                    _ = $hard.notified() => break,
                    Ok(()) = $kill.changed() => break,
                    _ = $goaway.notified() => conn.as_mut().graceful_shutdown(),
                }
            }
        }};
    }

    async fn serve_connection<S>(proto: Proto, tls: S, state: Arc<ServerState>, conn: usize)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let hard = Arc::new(Notify::new());
        let goaway = Arc::new(Notify::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let mut kill = state.kill.subscribe();
        let service = {
            let (state, hard, goaway) = (state.clone(), hard.clone(), goaway.clone());
            hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                let (state, hard, goaway, counter) =
                    (state.clone(), hard.clone(), goaway.clone(), counter.clone());
                async move {
                    Ok::<_, Infallible>(
                        handle_request(request, state, hard, goaway, conn, counter).await,
                    )
                }
            })
        };
        let io = TokioIo::new(tls);
        match proto {
            Proto::H2 => {
                let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service);
                drive!(connection, hard, goaway, kill);
            }
            Proto::H1 => {
                let connection =
                    hyper::server::conn::http1::Builder::new().serve_connection(io, service);
                drive!(connection, hard, goaway, kill);
            }
        }
    }

    impl TestServer {
        async fn start(proto: Proto, handler: Handler) -> TestServer {
            let (mut server_config, client_config) = self_signed_fixture();
            server_config.alpn_protocols = vec![match proto {
                Proto::H1 => b"http/1.1".to_vec(),
                Proto::H2 => b"h2".to_vec(),
            }];
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (kill, _) = watch::channel(());
            let state = Arc::new(ServerState {
                handler,
                accepts: AtomicUsize::new(0),
                live: AtomicUsize::new(0),
                requests: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                order: Mutex::new(Vec::new()),
                kill,
            });
            let accept = tokio::spawn({
                let state = state.clone();
                async move {
                    loop {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let conn = state.accepts.fetch_add(1, Ordering::SeqCst);
                        let (state, acceptor) = (state.clone(), acceptor.clone());
                        tokio::spawn(async move {
                            let Ok(tls) = acceptor.accept(tcp).await else {
                                return;
                            };
                            state.live.fetch_add(1, Ordering::SeqCst);
                            let _live = LiveGuard(state.clone());
                            serve_connection(proto, tls, state, conn).await;
                        });
                    }
                }
            });
            TestServer {
                addr,
                state,
                client: Arc::new(client_config),
                accept,
            }
        }

        fn backend(&self, method: DohMethod, timeout: Duration, pool: PoolConfig) -> DohBackend {
            DohBackend::new(DohBackendConfig {
                uri: Uri::from_str(&format!("https://localhost:{}/dns-query", self.addr.port()))
                    .unwrap(),
                method,
                tls_config: self.client.clone(),
                timeout,
            })
            .with_pool(pool)
        }

        /// The default pooled backend (POST, 5 s timeout).
        fn pooled(&self) -> DohBackend {
            self.backend(DohMethod::Post, Duration::from_secs(5), PoolConfig::new())
        }

        fn accepts(&self) -> usize {
            self.state.accepts.load(Ordering::SeqCst)
        }

        fn live(&self) -> usize {
            self.state.live.load(Ordering::SeqCst)
        }

        fn requests(&self) -> usize {
            self.state.requests.load(Ordering::SeqCst)
        }

        fn peak(&self) -> usize {
            self.state.peak.load(Ordering::SeqCst)
        }

        fn order(&self) -> Vec<String> {
            self.state.order.lock().unwrap().clone()
        }

        /// Drops every open connection.
        fn kill_all(&self) {
            self.state.kill.send_replace(());
        }
    }

    async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
        let limit = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < limit, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn ask(backend: &DohBackend, name: &str) -> Result<Message> {
        let query = query_for(name);
        let answer = backend.resolve(&query).await?;
        assert_eq!(answer.questions, query.questions, "answer to another query");
        assert_eq!(answer.header.id, query.header.id);
        Ok(answer)
    }

    #[tokio::test]
    async fn pooled_doh2_multiplexes_concurrent_queries_over_one_connection() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = Arc::new(server.pooled());

        let mut set = JoinSet::new();
        for i in 0..100 {
            let backend = backend.clone();
            set.spawn(async move { ask(&backend, &format!("q{i}.example.com")).await.unwrap() });
        }
        while let Some(done) = set.join_next().await {
            done.unwrap();
        }
        for i in 0..10 {
            ask(&backend, &format!("s{i}.example.com")).await.unwrap();
        }

        assert_eq!(server.accepts(), 1, "HTTP/2 shares one connection");
        let stats = backend.pool_stats();
        assert_eq!(stats.queries(), 110);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.in_flight(), 0);
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.queued(), 0, "100 queries fit the default capacity");
        assert!(stats.reused_queries() >= 10, "{stats:?}");
        assert_eq!(stats.unsolicited(), 0);
    }

    /// Opens one connection through `connector` and reports whether the
    /// client side of its TCP socket has `TCP_NODELAY` set.
    async fn client_socket_nodelay(mut connector: CountingConnector, server: &TestServer) -> bool {
        let uri = Uri::from_str(&format!(
            "https://localhost:{}/dns-query",
            server.addr.port()
        ))
        .unwrap();
        std::future::poll_fn(|cx| connector.poll_ready(cx))
            .await
            .unwrap();
        let connected = connector.call(uri).await.unwrap();
        match &connected.io {
            MaybeHttpsStream::Https(tls) => {
                tls.inner().get_ref().0.inner().inner().nodelay().unwrap()
            }
            MaybeHttpsStream::Http(_) => panic!("expected a TLS connection"),
        }
    }

    fn counting(inner: HttpsConnector<HttpConnector>) -> CountingConnector {
        CountingConnector {
            inner,
            counters: Arc::new(DohCounters::default()),
            generation: Arc::new(GenState::new()),
        }
    }

    #[tokio::test]
    async fn pooled_connections_set_tcp_nodelay_over_http1_and_http2() {
        for proto in [Proto::H1, Proto::H2] {
            let server = TestServer::start(proto, echo()).await;
            let pooled = counting(pooled_https_connector(&server.client));
            assert!(
                client_socket_nodelay(pooled, &server).await,
                "the pooled connector must set TCP_NODELAY"
            );

            // The probe is sensitive: a default connector leaves Nagle on.
            let default = counting(
                HttpsConnectorBuilder::new()
                    .with_tls_config((*server.client).clone())
                    .https_only()
                    .enable_http1()
                    .enable_http2()
                    .build(),
            );
            assert!(!client_socket_nodelay(default, &server).await);
        }
    }

    #[tokio::test]
    async fn pooled_doh2_reuses_the_connection_with_get() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = server.backend(DohMethod::Get, Duration::from_secs(5), PoolConfig::new());
        for i in 0..5 {
            ask(&backend, &format!("g{i}.example.com")).await.unwrap();
        }
        assert_eq!(server.accepts(), 1);
        assert_eq!(backend.pool_stats().reused_queries(), 4);
    }

    #[tokio::test]
    async fn pooled_doh1_keeps_alive_and_bounds_concurrency() {
        let server = TestServer::start(Proto::H1, echo()).await;
        let backend = server.pooled();
        for i in 0..5 {
            ask(&backend, &format!("k{i}.example.com")).await.unwrap();
        }
        assert_eq!(
            server.accepts(),
            1,
            "HTTP/1.1 keep-alive reuses the connection"
        );
        drop(backend);

        let hold = Arc::new(Semaphore::new(0));
        let server = TestServer::start(Proto::H1, {
            let hold = hold.clone();
            handler(move |ctx| {
                let hold = hold.clone();
                async move { Action::Hold(hold, reply_to(&ctx.query)) }
            })
        })
        .await;
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(10),
            PoolConfig::new().max_connections(1).max_in_flight(2),
        ));
        let mut set = JoinSet::new();
        for i in 0..6 {
            let backend = backend.clone();
            set.spawn(async move { ask(&backend, &format!("h{i}.example.com")).await });
        }
        wait_for("two requests at the server", || server.requests() == 2).await;
        wait_for("four queued calls", || backend.pool_stats().queued() == 4).await;
        assert_eq!(server.requests(), 2, "at most two queries are in flight");
        hold.add_permits(6);
        while let Some(done) = set.join_next().await {
            done.unwrap().unwrap();
        }
        assert!(server.peak() <= 2, "peak {}", server.peak());
    }

    #[tokio::test]
    async fn pooled_doh2_reconnects_after_the_server_closes_the_connection() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = server.pooled();
        ask(&backend, "one.example.com").await.unwrap();
        server.kill_all();
        wait_for("the client to see the close", || {
            backend.pool_stats().connections_open() == 0
        })
        .await;

        ask(&backend, "two.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2);
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.retries(), 0, "an idle close needs no retry");
    }

    #[tokio::test]
    async fn pooled_doh2_reconnects_after_goaway() {
        let server = TestServer::start(
            Proto::H2,
            handler(|ctx| async move {
                if ctx.conn == 0 {
                    Action::ReplyThenGoaway(reply_to(&ctx.query))
                } else {
                    Action::Reply(reply_to(&ctx.query))
                }
            }),
        )
        .await;
        let backend = server.pooled();
        ask(&backend, "one.example.com").await.unwrap();
        wait_for("the GOAWAY connection to close", || {
            backend.pool_stats().connections_open() == 0
        })
        .await;
        ask(&backend, "two.example.com").await.unwrap();
        ask(&backend, "three.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2);
        assert_eq!(backend.pool_stats().connections_opened(), 2);
    }

    #[tokio::test]
    async fn pooled_doh2_retries_once_when_a_reused_connection_dies_mid_flight() {
        let server = TestServer::start(
            Proto::H2,
            handler(|ctx| async move {
                if ctx.conn == 0 && ctx.nth >= 1 {
                    Action::Hangup
                } else {
                    Action::Reply(reply_to(&ctx.query))
                }
            }),
        )
        .await;
        let backend = server.pooled();
        ask(&backend, "one.example.com").await.unwrap();
        ask(&backend, "two.example.com")
            .await
            .expect("the query is resent on a fresh connection");
        assert_eq!(server.accepts(), 2);
        assert_eq!(backend.pool_stats().retries(), 1);
        ask(&backend, "three.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2);
    }

    #[tokio::test]
    async fn pooled_doh2_does_not_retry_a_failure_on_a_fresh_connection() {
        let server = TestServer::start(Proto::H2, handler(|_| async { Action::Hangup })).await;
        let backend = server.pooled();
        let err = ask(&backend, "one.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(server.accepts(), 1, "a fresh connection is not retried");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(backend.pool_stats().in_flight(), 0);
    }

    #[tokio::test]
    async fn pooled_doh2_never_retries_a_second_failure() {
        // The server hangs up on every "bad" query. The first send fails on
        // the reused connection and is resent once; the resend fails on a
        // fresh connection, and the error must surface instead of looping.
        let server = TestServer::start(
            Proto::H2,
            handler(|ctx| async move {
                if ctx.query.questions[0].name.to_string().starts_with("bad") {
                    Action::Hangup
                } else {
                    Action::Reply(reply_to(&ctx.query))
                }
            }),
        )
        .await;
        let backend = server.pooled();
        ask(&backend, "ok.example.com").await.unwrap();
        let err = ask(&backend, "bad.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 1, "exactly one resend");
        assert_eq!(
            server.accepts(),
            2,
            "the resend failed on a fresh connection"
        );
        ask(&backend, "after.example.com").await.unwrap();
    }

    #[tokio::test]
    async fn pooled_doh2_does_not_retry_a_timeout_and_the_connection_survives() {
        let never = Arc::new(Semaphore::new(0));
        let server = TestServer::start(
            Proto::H2,
            handler(move |ctx| {
                let never = never.clone();
                async move {
                    if ctx.nth == 1 {
                        Action::Hold(never, reply_to(&ctx.query))
                    } else {
                        Action::Reply(reply_to(&ctx.query))
                    }
                }
            }),
        )
        .await;
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_millis(400),
            PoolConfig::new(),
        );
        ask(&backend, "one.example.com").await.unwrap();
        let started = Instant::now();
        let err = ask(&backend, "stuck.example.com").await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(backend.pool_stats().retries(), 0);
        ask(&backend, "three.example.com").await.unwrap();
        assert_eq!(server.accepts(), 1, "a timeout leaves the connection alone");
        assert_eq!(backend.pool_stats().in_flight(), 0);
    }

    #[tokio::test]
    async fn pooled_doh2_isolates_bad_answers_to_their_own_query() {
        let server = TestServer::start(
            Proto::H2,
            handler(|ctx| async move {
                let name = ctx.query.questions[0].name.to_string();
                if name.starts_with("status") {
                    Action::Status(500)
                } else if name.starts_with("garbage") {
                    Action::Garbage
                } else if name.starts_with("wrong") {
                    Action::Reply(reply_to(&query_for("other.example.org")))
                } else {
                    Action::Reply(reply_to(&ctx.query))
                }
            }),
        )
        .await;
        let backend = Arc::new(server.pooled());
        let mut set = JoinSet::new();
        for name in [
            "a.example.com",
            "status.example.com",
            "b.example.com",
            "garbage.example.com",
            "c.example.com",
            "wrong.example.com",
            "d.example.com",
        ] {
            let backend = backend.clone();
            set.spawn(async move { (name, ask(&backend, name).await) });
        }
        while let Some(done) = set.join_next().await {
            let (name, result) = done.unwrap();
            match name {
                "status.example.com" | "wrong.example.com" => {
                    assert!(
                        matches!(result, Err(Error::Transport(_))),
                        "{name}: {result:?}"
                    );
                }
                "garbage.example.com" => {
                    assert!(matches!(result, Err(Error::Truncated { .. })), "{result:?}");
                }
                _ => {
                    result.unwrap();
                }
            }
        }
        ask(&backend, "after.example.com").await.unwrap();
        assert_eq!(
            backend.pool_stats().retries(),
            0,
            "bad answers are not retried"
        );
        assert_eq!(
            server.accepts(),
            1,
            "bad answers leave the connection alone"
        );
    }

    #[tokio::test]
    async fn pooled_doh2_never_resends_a_non_query_opcode() {
        let server = TestServer::start(
            Proto::H2,
            handler(|ctx| async move {
                if ctx.nth >= 1 && ctx.conn == 0 {
                    Action::Hangup
                } else {
                    Action::Reply(reply_to(&ctx.query))
                }
            }),
        )
        .await;
        let backend = server.pooled();
        ask(&backend, "one.example.com").await.unwrap();
        let mut notify = query_for("two.example.com");
        notify.header.opcode = Opcode::Notify;
        let err = backend.resolve(&notify).await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(server.accepts(), 1, "the NOTIFY was not sent again");
    }

    #[tokio::test]
    async fn pooled_doh2_replaces_the_client_at_the_maximum_lifetime() {
        let slow = Arc::new(Semaphore::new(0));
        let server = TestServer::start(
            Proto::H2,
            handler({
                let slow = slow.clone();
                move |ctx| {
                    let slow = slow.clone();
                    async move {
                        if ctx.query.questions[0].name.to_string().starts_with("slow") {
                            Action::Hold(slow, reply_to(&ctx.query))
                        } else {
                            Action::Reply(reply_to(&ctx.query))
                        }
                    }
                }
            }),
        )
        .await;
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(20),
            PoolConfig::new().max_lifetime(Some(Duration::from_secs(1))),
        ));
        let in_flight = tokio::spawn({
            let backend = backend.clone();
            async move { ask(&backend, "slow.example.com").await }
        });
        wait_for("the slow query at the server", || server.requests() == 1).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // The old client still has a query in flight; new queries use a new
        // client and a new connection and nothing fails.
        ask(&backend, "two.example.com").await.unwrap();
        ask(&backend, "three.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2);
        assert_eq!(
            backend.pool_stats().closed_lifetime(),
            0,
            "old query still runs"
        );

        slow.add_permits(1);
        in_flight
            .await
            .unwrap()
            .expect("the query in flight during rotation completes");
        wait_for("the old connection to close", || {
            backend.pool_stats().closed_lifetime() == 1
        })
        .await;
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.in_flight(), 0);
        assert_eq!(
            server.accepts(),
            2,
            "later queries share the new connection"
        );
    }

    #[tokio::test]
    async fn pooled_doh_closes_idle_connections_after_the_idle_timeout() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::new().idle_timeout(Duration::from_secs(1)),
        );
        ask(&backend, "one.example.com").await.unwrap();
        wait_for("the idle connection to close", || {
            backend.pool_stats().connections_open() == 0
        })
        .await;
        wait_for("the server to see the close", || server.live() == 0).await;
        ask(&backend, "two.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2);
    }

    #[tokio::test]
    async fn pooled_doh2_admits_in_arrival_order_within_the_bound() {
        let hold = Arc::new(Semaphore::new(0));
        let server = TestServer::start(
            Proto::H2,
            handler({
                let hold = hold.clone();
                move |ctx| {
                    let hold = hold.clone();
                    async move {
                        if ctx.query.questions[0].name.to_string().starts_with('q') {
                            Action::Hold(hold, reply_to(&ctx.query))
                        } else {
                            Action::Reply(reply_to(&ctx.query))
                        }
                    }
                }
            }),
        )
        .await;
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(20),
            PoolConfig::new().max_connections(1).max_in_flight(2),
        ));
        // Warm the connection first: a cold start sends one query at a time
        // until the HTTP version is known.
        ask(&backend, "warm.example.com").await.unwrap();
        let mut set = JoinSet::new();
        for i in 0..6 {
            let backend = backend.clone();
            set.spawn(async move { ask(&backend, &format!("q{i}.example.com")).await });
        }
        wait_for("two held requests at the server", || server.requests() == 3).await;
        wait_for("four queued calls", || backend.pool_stats().queued() == 4).await;
        assert_eq!(backend.pool_stats().in_flight(), 2);
        assert_eq!(server.requests(), 3, "capacity is two");

        for released in 1..=4 {
            hold.add_permits(1);
            wait_for("the next queued query", || {
                server.requests() == 3 + released
            })
            .await;
        }
        hold.add_permits(2);
        while let Some(done) = set.join_next().await {
            done.unwrap().unwrap();
        }
        assert!(server.peak() <= 2, "peak {}", server.peak());
        let order = server.order();
        assert_eq!(
            &order[3..],
            [
                "q2.example.com.",
                "q3.example.com.",
                "q4.example.com.",
                "q5.example.com."
            ],
            "queued calls are admitted in arrival order"
        );
        let stats = backend.pool_stats();
        assert_eq!(
            (stats.queries(), stats.in_flight(), stats.queued()),
            (7, 0, 4)
        );
        assert_eq!(server.accepts(), 1);
    }

    #[tokio::test]
    async fn pooled_doh2_cancelled_calls_release_their_capacity() {
        let hold = Arc::new(Semaphore::new(0));
        let server = TestServer::start(
            Proto::H2,
            handler({
                let hold = hold.clone();
                move |ctx| {
                    let hold = hold.clone();
                    async move {
                        if ctx.query.questions[0].name.to_string().starts_with("hold") {
                            Action::Hold(hold, reply_to(&ctx.query))
                        } else {
                            Action::Reply(reply_to(&ctx.query))
                        }
                    }
                }
            }),
        )
        .await;
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(20),
            PoolConfig::new().max_connections(1).max_in_flight(1),
        ));
        let holder = tokio::spawn({
            let backend = backend.clone();
            async move { ask(&backend, "hold.example.com").await }
        });
        wait_for("the held query at the server", || server.requests() == 1).await;
        let waiter = tokio::spawn({
            let backend = backend.clone();
            async move { ask(&backend, "waiter.example.com").await }
        });
        wait_for("a queued call", || backend.pool_stats().queued() == 1).await;

        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        holder.abort();
        assert!(holder.await.unwrap_err().is_cancelled());
        wait_for("capacity to return", || {
            backend.pool_stats().in_flight() == 0
        })
        .await;

        ask(&backend, "after.example.com").await.unwrap();
        assert_eq!(
            server.accepts(),
            1,
            "cancellation leaves the connection usable"
        );
        assert_eq!(backend.pool_stats().in_flight(), 0);
    }

    #[tokio::test]
    async fn pooled_doh2_a_call_waiting_for_capacity_times_out_instead_of_waiting_forever() {
        let never = Arc::new(Semaphore::new(0));
        let server = TestServer::start(
            Proto::H2,
            handler(move |ctx| {
                let never = never.clone();
                async move { Action::Hold(never, reply_to(&ctx.query)) }
            }),
        )
        .await;
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_millis(500),
            PoolConfig::new().max_connections(1).max_in_flight(1),
        ));
        let holder = tokio::spawn({
            let backend = backend.clone();
            async move { ask(&backend, "holder.example.com").await }
        });
        wait_for("the held query at the server", || server.requests() == 1).await;
        let started = Instant::now();
        let err = ask(&backend, "waiter.example.com").await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert!(started.elapsed() < Duration::from_millis(2500));
        assert_eq!(holder.await.unwrap().unwrap_err(), Error::Timeout);
        assert_eq!(backend.pool_stats().in_flight(), 0);
        assert!(backend.pool_stats().queued() >= 1);
    }

    #[tokio::test]
    async fn pooled_doh_burst_against_an_unreachable_server_fails_every_call() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = Arc::new(server.pooled());
        // Stop the server's listener: connections are refused from now on.
        server.accept.abort();
        wait_for("the listener to stop", || server.accept.is_finished()).await;
        let mut set = JoinSet::new();
        for i in 0..20 {
            let backend = backend.clone();
            set.spawn(async move { ask(&backend, &format!("q{i}.example.com")).await });
        }
        while let Some(done) = set.join_next().await {
            let err = done.unwrap().unwrap_err();
            assert!(matches!(err, Error::Transport(_)), "{err:?}");
        }
        let stats = backend.pool_stats();
        assert_eq!((stats.in_flight(), stats.connections_open()), (0, 0));
        assert_eq!(stats.retries(), 0);
    }

    #[tokio::test]
    async fn disabled_pool_opens_a_connection_per_query() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::disabled(),
        );
        for i in 0..3 {
            ask(&backend, &format!("d{i}.example.com")).await.unwrap();
        }
        assert_eq!(
            server.accepts(),
            3,
            "one connection per query, as before reuse"
        );
        assert_eq!(backend.pool_stats(), PoolStats::default());
        wait_for("per-query connections to close", || server.live() == 0).await;
    }

    #[tokio::test]
    async fn dropping_a_pooled_backend_closes_its_connection() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let backend = server.pooled();
        ask(&backend, "one.example.com").await.unwrap();
        assert_eq!(server.live(), 1);
        drop(backend);
        wait_for("the connection to close", || server.live() == 0).await;
    }

    #[tokio::test]
    async fn pooled_backends_never_share_connections_or_tls_identity() {
        let server = TestServer::start(Proto::H2, echo()).await;
        let first = server.pooled();
        let second = server.pooled();
        ask(&first, "one.example.com").await.unwrap();
        ask(&second, "two.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2, "each backend owns its connection");

        let (_other_server, untrusting) = self_signed_fixture();
        let strict = DohBackend::new(DohBackendConfig {
            uri: Uri::from_str(&format!(
                "https://localhost:{}/dns-query",
                server.addr.port()
            ))
            .unwrap(),
            method: DohMethod::Post,
            tls_config: Arc::new(untrusting),
            timeout: Duration::from_secs(5),
        });
        let err = ask(&strict, "three.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Tls(_)), "{err:?}");
        assert_eq!(
            strict.pool_stats().retries(),
            0,
            "a TLS error is not retried"
        );
        assert_eq!(strict.pool_stats().connections_opened(), 0);
        ask(&first, "four.example.com").await.unwrap();
        assert_eq!(server.accepts(), 2 + 1 /* the rejected handshake */);
    }

    #[test]
    fn a_pooled_backend_recovers_on_a_new_runtime() {
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = server_runtime.block_on(TestServer::start(Proto::H2, echo()));
        let backend = Arc::new(server.pooled());
        for name in ["one.example.com", "two.example.com"] {
            // Each runtime is dropped after its query, taking the client's
            // connection task with it.
            let backend = backend.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(ask(&backend, name)).unwrap();
            })
            .join()
            .unwrap();
        }
        assert_eq!(server.accepts(), 2, "the second runtime reconnected");
    }

    // ----- pooled HTTP/3: a scripted loopback server -----

    /// What the scripted HTTP/3 server does with one request.
    enum H3Action {
        /// Answers with the echo of the query after a delay. A write that the
        /// client has cancelled by then is recorded.
        Echo(Duration),
        /// Answers with this message.
        Reply(Message),
        /// Answers with this HTTP status and no body.
        Status(u16),
        /// Closes the connection without answering.
        Close,
        /// Answers, then closes the connection once the client has had time to
        /// read the answer.
        EchoThenClose,
        /// Resets the request stream, leaving the connection open.
        ResetStream,
        /// Sends the status line, then more data after a delay (a write the
        /// client has stopped by then is recorded).
        StatusThenStall(u16),
    }

    #[derive(Default)]
    struct H3Counters {
        /// Connections whose handshake completed.
        accepted: AtomicUsize,
        /// Connections that ended.
        closed: AtomicUsize,
        /// Requests received.
        requests: AtomicUsize,
        /// Requests being served right now.
        active: AtomicUsize,
        /// The most requests served at once.
        max_active: AtomicUsize,
        /// Requests the client cancelled before they were answered.
        cancelled: AtomicUsize,
        /// The code of the last such cancellation.
        cancel_code: AtomicUsize,
    }

    impl H3Counters {
        fn get(counter: &AtomicUsize) -> usize {
            counter.load(Ordering::SeqCst)
        }
    }

    /// Scripted by `(connection index, request index on it, query)`.
    type H3Script = Arc<dyn Fn(usize, usize, &Message) -> H3Action + Send + Sync>;

    struct H3Server {
        addr: std::net::SocketAddr,
        counters: Arc<H3Counters>,
        client: Arc<ClientConfig>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for H3Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

    async fn respond(
        stream: &mut ServerStream,
        status: u16,
        body: Vec<u8>,
    ) -> std::result::Result<(), H3StreamError> {
        stream
            .send_response(
                http::Response::builder()
                    .status(status)
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap(),
            )
            .await?;
        if !body.is_empty() {
            stream.send_data(Bytes::from(body)).await?;
        }
        stream.finish().await
    }

    async fn serve_h3_request(
        resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
        connection: quinn::Connection,
        (conn_index, request_index): (usize, usize),
        script: H3Script,
        counters: Arc<H3Counters>,
    ) {
        let Ok((request, mut stream)) = resolver.resolve_request().await else {
            return;
        };
        let wire = if request.method() == hyper::Method::GET {
            let encoded = request
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")))
                .expect("a GET request carries the dns parameter");
            URL_SAFE_NO_PAD.decode(encoded).unwrap()
        } else {
            let mut body = Vec::new();
            while let Ok(Some(mut chunk)) = stream.recv_data().await {
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            body
        };
        let query = Message::decode(&wire).unwrap();
        counters.requests.fetch_add(1, Ordering::SeqCst);
        let active = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
        counters.max_active.fetch_max(active, Ordering::SeqCst);
        let outcome = match script(conn_index, request_index, &query) {
            H3Action::Echo(delay) => {
                tokio::time::sleep(delay).await;
                respond(&mut stream, 200, reply_to(&query).encode().unwrap()).await
            }
            H3Action::Reply(message) => respond(&mut stream, 200, message.encode().unwrap()).await,
            H3Action::Status(status) => respond(&mut stream, status, Vec::new()).await,
            H3Action::Close => {
                connection.close(7u32.into(), b"scripted close");
                Ok(())
            }
            H3Action::EchoThenClose => {
                let sent = respond(&mut stream, 200, reply_to(&query).encode().unwrap()).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                connection.close(H3_NO_ERROR.into(), b"done");
                sent
            }
            H3Action::ResetStream => {
                stream.stop_stream(H3Code::H3_INTERNAL_ERROR);
                Ok(())
            }
            H3Action::StatusThenStall(status) => {
                let sent = stream
                    .send_response(http::Response::builder().status(status).body(()).unwrap())
                    .await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                match sent {
                    Ok(()) => stream.send_data(Bytes::from_static(b"late body")).await,
                    Err(err) => Err(err),
                }
            }
        };
        if let Err(H3StreamError::RemoteTerminate { code, .. }) = outcome {
            counters
                .cancel_code
                .store(usize::try_from(code.value()).unwrap(), Ordering::SeqCst);
            counters.cancelled.fetch_add(1, Ordering::SeqCst);
        }
        counters.active.fetch_sub(1, Ordering::SeqCst);
    }

    async fn serve_h3_connection(
        connection: quinn::Connection,
        index: usize,
        script: H3Script,
        counters: Arc<H3Counters>,
    ) {
        let raw = connection.clone();
        let Ok(mut h3_connection) =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await
        else {
            return;
        };
        let mut next = 0;
        while let Ok(Some(resolver)) = h3_connection.accept().await {
            let request = next;
            next += 1;
            tokio::spawn(serve_h3_request(
                resolver,
                raw.clone(),
                (index, request),
                Arc::clone(&script),
                Arc::clone(&counters),
            ));
        }
        counters.closed.fetch_add(1, Ordering::SeqCst);
    }

    fn serve_h3(
        script: impl Fn(usize, usize, &Message) -> H3Action + Send + Sync + 'static,
    ) -> H3Server {
        let (server_config, client_config) = http3_fixture();
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let script: H3Script = Arc::new(script);
        let counters = Arc::new(H3Counters::default());
        let shared = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            let mut next = 0;
            while let Some(incoming) = endpoint.accept().await {
                let index = next;
                next += 1;
                let (script, counters) = (Arc::clone(&script), Arc::clone(&shared));
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    counters.accepted.fetch_add(1, Ordering::SeqCst);
                    serve_h3_connection(connection, index, script, counters).await;
                });
            }
        });
        H3Server {
            addr,
            counters,
            client: Arc::new(client_config),
            task,
        }
    }

    fn h3_echo() -> H3Server {
        serve_h3(|_, _, _| H3Action::Echo(Duration::ZERO))
    }

    impl H3Server {
        fn backend(&self, method: DohMethod, timeout: Duration, pool: PoolConfig) -> Doh3Backend {
            Doh3Backend::new(Doh3BackendConfig {
                uri: Uri::from_str(&format!("https://localhost:{}/dns-query", self.addr.port()))
                    .unwrap(),
                server: self.addr,
                method,
                tls_config: self.client.clone(),
                timeout,
            })
            .with_pool(pool)
        }

        fn pooled(&self) -> Doh3Backend {
            self.backend(DohMethod::Post, Duration::from_secs(5), PoolConfig::new())
        }

        fn accepted(&self) -> usize {
            H3Counters::get(&self.counters.accepted)
        }
    }

    async fn ask3(backend: &Doh3Backend, name: &str) -> Result<Message> {
        let query = query_for(name);
        let answer = backend.resolve(&query).await?;
        assert_eq!(answer.questions, query.questions, "answer to another query");
        assert_eq!(answer.header.id, query.header.id);
        Ok(answer)
    }

    #[tokio::test]
    async fn pooled_doh3_sequential_queries_share_one_connection() {
        let server = h3_echo();
        let backend = server.pooled();
        for i in 0..5 {
            ask3(&backend, &format!("q{i}.example.com")).await.unwrap();
        }
        let stats = backend.pool_stats();
        assert_eq!(server.accepted(), 1);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.queries(), 5);
        assert_eq!(stats.reused_queries(), 4);
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.in_flight(), 0);
    }

    #[tokio::test]
    async fn pooled_doh3_resolves_with_get() {
        let server = h3_echo();
        let backend = server.backend(DohMethod::Get, Duration::from_secs(5), PoolConfig::new());
        for i in 0..3 {
            ask3(&backend, &format!("g{i}.example.com")).await.unwrap();
        }
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn disabled_doh3_pool_opens_one_connection_per_query() {
        // Negative control for the reuse test above: the 1.1 behaviour.
        let server = h3_echo();
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::disabled(),
        );
        for i in 0..3 {
            ask3(&backend, &format!("d{i}.example.com")).await.unwrap();
        }
        assert_eq!(server.accepted(), 3);
        assert_eq!(backend.pool_stats(), PoolStats::default());
    }

    #[tokio::test]
    async fn pooled_doh3_multiplexes_concurrent_queries_within_the_connection_bound() {
        let server = serve_h3(|_, _, _| H3Action::Echo(Duration::from_millis(30)));
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::new().max_connections(2),
        ));
        let mut set = JoinSet::new();
        for i in 0..40 {
            let backend = backend.clone();
            set.spawn(async move { ask3(&backend, &format!("h{i}.example.com")).await.unwrap() });
        }
        while let Some(done) = set.join_next().await {
            done.unwrap();
        }
        let stats = backend.pool_stats();
        assert!(server.accepted() <= 2, "{}", server.accepted());
        assert!(stats.connections_opened() <= 2, "{stats:?}");
        assert_eq!(stats.queries(), 40);
        assert_eq!(stats.in_flight(), 0);
        assert!(
            H3Counters::get(&server.counters.max_active) > 2,
            "requests ran side by side on streams"
        );
    }

    #[tokio::test]
    async fn pooled_doh3_max_in_flight_bounds_the_requests_and_queues_the_rest() {
        let server = serve_h3(|_, _, _| H3Action::Echo(Duration::from_millis(30)));
        let backend = Arc::new(server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::new().max_connections(1).max_in_flight(2),
        ));
        let mut set = JoinSet::new();
        for i in 0..8 {
            let backend = backend.clone();
            set.spawn(async move { ask3(&backend, &format!("h{i}.example.com")).await.unwrap() });
        }
        while let Some(done) = set.join_next().await {
            done.unwrap();
        }
        assert!(H3Counters::get(&server.counters.max_active) <= 2);
        assert_eq!(server.accepted(), 1);
        assert!(backend.pool_stats().queued() > 0);
    }

    #[tokio::test]
    async fn pooled_doh3_retries_once_when_a_reused_connection_closes_mid_flight() {
        // The first connection answers one query, then closes on the second.
        let server = serve_h3(|conn, nth, _| {
            if conn == 0 && nth == 1 {
                H3Action::Close
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        ask3(&backend, "two.example.com")
            .await
            .expect("the retry on a fresh connection answers");
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 1);
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(server.accepted(), 2);
    }

    #[tokio::test]
    async fn pooled_doh3_does_not_retry_a_fresh_connection_that_closes() {
        let server = serve_h3(|_, _, _| H3Action::Close);
        let backend = server.pooled();
        let err = ask3(&backend, "one.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_never_retries_a_second_failure() {
        let server = serve_h3(|conn, nth, _| {
            if conn == 0 && nth == 0 {
                H3Action::Echo(Duration::ZERO)
            } else {
                H3Action::Close
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        let err = ask3(&backend, "two.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 1, "retried exactly once");
        assert_eq!(server.accepted(), 2);
    }

    #[tokio::test]
    async fn pooled_doh3_never_resends_a_non_query_opcode() {
        let server = serve_h3(|conn, nth, _| {
            if conn == 0 && nth == 1 {
                H3Action::Close
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        let mut notify = query_for("two.example.com");
        notify.header.opcode = Opcode::Notify;
        let err = backend.resolve(&notify).await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        assert_eq!(backend.pool_stats().retries(), 0);
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_replaces_a_connection_the_peer_already_closed_without_a_retry() {
        let server = serve_h3(|conn, _, _| {
            if conn == 0 {
                H3Action::EchoThenClose
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        wait_for("the client to notice the close", || {
            backend.pool_stats().connections_open() == 0
        })
        .await;
        ask3(&backend, "two.example.com").await.unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0, "liveness is checked before use");
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_error(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_does_not_retry_a_reset_stream_on_a_connection_that_answered() {
        // Negative control for the retry rule: the connection had answered a
        // query, but only one request was reset and the connection stayed
        // open, so nothing is resent and the connection is kept.
        let server = serve_h3(|_, nth, _| {
            if nth == 1 {
                H3Action::ResetStream
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        let err = ask3(&backend, "two.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        ask3(&backend, "three.example.com")
            .await
            .expect("the same connection still works");
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.closed_error(), 0);
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_does_not_retry_an_http_error_and_keeps_the_connection() {
        let server = serve_h3(|_, nth, _| {
            if nth == 1 {
                H3Action::Status(503)
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        let err = ask3(&backend, "two.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        ask3(&backend, "three.example.com").await.unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_a_mismatched_answer_fails_only_its_query() {
        let server = serve_h3(|_, _, query| {
            if query.questions[0].name == Name::from_ascii("bad.example.com").unwrap() {
                H3Action::Reply(answer_for("other.example.org", 0))
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        let err = ask3(&backend, "bad.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        ask3(&backend, "good.example.com").await.unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.closed_error(), 0);
    }

    #[tokio::test]
    async fn pooled_doh3_a_dropped_call_cancels_its_request_and_keeps_the_connection() {
        let server = serve_h3(|_, nth, _| {
            if nth == 0 {
                H3Action::Echo(Duration::from_millis(600))
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        let cancelled = tokio::time::timeout(
            Duration::from_millis(150),
            backend.resolve(&query_for("held.example.com")),
        )
        .await;
        assert!(cancelled.is_err(), "the held query was dropped");
        assert_eq!(backend.pool_stats().in_flight(), 0);
        wait_for("the server to see the cancellation", || {
            H3Counters::get(&server.counters.cancelled) == 1
        })
        .await;
        ask3(&backend, "next.example.com")
            .await
            .expect("the connection is still usable");
        assert_eq!(backend.pool_stats().connections_opened(), 1);
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_a_timed_out_query_is_cancelled_and_not_retried() {
        let server = serve_h3(|_, nth, _| {
            if nth == 1 {
                H3Action::Echo(Duration::from_millis(700))
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_millis(250),
            PoolConfig::new(),
        );
        ask3(&backend, "one.example.com").await.unwrap();
        let err = ask3(&backend, "two.example.com").await.unwrap_err();
        assert_eq!(err, Error::Timeout);
        let stats = backend.pool_stats();
        assert_eq!(stats.retries(), 0);
        assert_eq!(
            stats.connections_open(),
            1,
            "one timeout keeps the connection"
        );
        wait_for("the server to see the cancellation", || {
            H3Counters::get(&server.counters.cancelled) == 1
        })
        .await;
        ask3(&backend, "three.example.com").await.unwrap();
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn pooled_doh3_abandoning_a_failed_response_stops_it_with_h3_request_cancelled() {
        // The server answers 503 and keeps the response open; the query fails
        // at the status, so its request is abandoned while the response is
        // still being sent, and the server sees the literal cancel code.
        let server = serve_h3(|_, nth, _| {
            if nth == 1 {
                H3Action::StatusThenStall(503)
            } else {
                H3Action::Echo(Duration::ZERO)
            }
        });
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        let err = ask3(&backend, "two.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        wait_for("the server to see the cancellation", || {
            H3Counters::get(&server.counters.cancelled) == 1
        })
        .await;
        assert_eq!(
            H3Counters::get(&server.counters.cancel_code),
            0x10c,
            "H3_REQUEST_CANCELLED"
        );
        ask3(&backend, "three.example.com").await.unwrap();
        let stats = backend.pool_stats();
        assert_eq!((stats.retries(), stats.connections_opened()), (0, 1));
    }

    #[tokio::test]
    async fn pooled_doh3_closes_an_idle_connection_after_the_idle_timeout() {
        let server = h3_echo();
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::new().idle_timeout(Duration::from_secs(1)),
        );
        ask3(&backend, "one.example.com").await.unwrap();
        assert_eq!(backend.pool_stats().connections_open(), 1);
        tokio::time::sleep(Duration::from_millis(1400)).await;
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(stats.closed_idle(), 1);
        wait_for("the server to see the close", || {
            H3Counters::get(&server.counters.closed) == 1
        })
        .await;
        ask3(&backend, "two.example.com").await.unwrap();
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.retries(), 0);
    }

    #[tokio::test]
    async fn pooled_doh3_rotates_a_connection_at_its_maximum_lifetime() {
        let server = h3_echo();
        let backend = server.backend(
            DohMethod::Post,
            Duration::from_secs(5),
            PoolConfig::new().max_lifetime(Some(Duration::from_secs(1))),
        );
        ask3(&backend, "one.example.com").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        ask3(&backend, "two.example.com")
            .await
            .expect("the replacement answers without a failed query");
        let stats = backend.pool_stats();
        assert_eq!(stats.connections_opened(), 2);
        assert_eq!(stats.closed_lifetime(), 1);
        assert_eq!(stats.retries(), 0);
    }

    #[tokio::test]
    async fn dropping_a_pooled_doh3_backend_closes_its_connection() {
        let server = h3_echo();
        let backend = server.pooled();
        ask3(&backend, "one.example.com").await.unwrap();
        assert_eq!(H3Counters::get(&server.counters.closed), 0);
        drop(backend);
        wait_for("the server to see the close", || {
            H3Counters::get(&server.counters.closed) == 1
        })
        .await;
    }

    #[tokio::test]
    async fn pooled_doh3_backends_never_share_connections_or_tls_identity() {
        let server = h3_echo();
        let (first, second) = (server.pooled(), server.pooled());
        ask3(&first, "one.example.com").await.unwrap();
        ask3(&second, "two.example.com").await.unwrap();
        assert_eq!(server.accepted(), 2, "each backend owns its connection");

        let (_other_server, untrusting) = self_signed_fixture();
        let strict = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_str(&format!(
                "https://localhost:{}/dns-query",
                server.addr.port()
            ))
            .unwrap(),
            server: server.addr,
            method: DohMethod::Post,
            tls_config: Arc::new(untrusting),
            timeout: Duration::from_secs(5),
        });
        let err = ask3(&strict, "three.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Tls(_)), "{err:?}");
        let stats = strict.pool_stats();
        assert_eq!((stats.retries(), stats.connections_opened()), (0, 0));
        ask3(&first, "four.example.com").await.unwrap();
        assert_eq!(
            server.accepted(),
            2,
            "the rejected handshake never completed"
        );
    }

    #[test]
    fn a_pooled_doh3_backend_rebinds_its_endpoint_on_a_new_runtime() {
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = server_runtime.block_on(async { h3_echo() });
        let backend = Arc::new(server.pooled());
        for name in ["one.example.com", "two.example.com"] {
            // Each runtime is dropped after its query, taking the endpoint's
            // driver and the connection's tasks with it.
            let backend = backend.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(ask3(&backend, name)).unwrap();
            })
            .join()
            .unwrap();
        }
        assert_eq!(server.accepted(), 2, "the second runtime reconnected");
    }

    #[test]
    fn the_h3_alpn_is_fixed_at_construction_and_the_callers_config_is_untouched() {
        let (_server_config, client_config) = http3_fixture();
        assert!(client_config.alpn_protocols.is_empty());
        let tls = Arc::new(client_config);
        let backend = Doh3Backend::new(Doh3BackendConfig {
            uri: Uri::from_static("https://localhost:853/dns-query"),
            server: "127.0.0.1:853".parse().unwrap(),
            method: DohMethod::Post,
            tls_config: tls.clone(),
            timeout: Duration::from_secs(1),
        });
        assert_eq!(backend.tls_config.alpn_protocols, vec![b"h3".to_vec()]);
        assert!(tls.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn doh3_without_a_uri_host_is_a_transport_error_pooled_or_not() {
        let (_server_config, client_config) = http3_fixture();
        for pool in [PoolConfig::new(), PoolConfig::disabled()] {
            let backend = Doh3Backend::new(Doh3BackendConfig {
                uri: Uri::from_static("/dns-query"),
                server: "127.0.0.1:853".parse().unwrap(),
                method: DohMethod::Post,
                tls_config: Arc::new(client_config.clone()),
                timeout: Duration::from_secs(1),
            })
            .with_pool(pool);
            let err = backend
                .resolve(&query_for("example.com"))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Transport(_)), "{err:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_retry_rule_needs_every_condition() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let closed = |error: Error| H3Failure {
            error,
            closed: true,
            answered: true,
        };
        let base = closed(Error::Transport("connection closed".to_string()));
        assert!(retry_allowed(&base, true, false, now, later), "baseline");

        // Each guard, flipped on its own, forbids the retry.
        let not_closed = H3Failure {
            closed: false,
            ..closed(Error::Transport("stream reset".to_string()))
        };
        assert!(
            !retry_allowed(&not_closed, true, false, now, later),
            "closed"
        );
        let not_answered = H3Failure {
            answered: false,
            ..closed(Error::Transport("connection closed".to_string()))
        };
        assert!(
            !retry_allowed(&not_answered, true, false, now, later),
            "reused"
        );
        assert!(
            !retry_allowed(&base, false, false, now, later),
            "QUERY only"
        );
        assert!(!retry_allowed(&base, true, true, now, later), "not twice");
        assert!(!retry_allowed(&base, true, false, later, later), "deadline");
        assert!(
            !retry_allowed(&base, true, false, later + Duration::from_millis(1), later),
            "past the deadline"
        );
        assert!(
            !retry_allowed(&closed(Error::Timeout), true, false, now, later),
            "never on a timeout"
        );
        assert!(
            !retry_allowed(
                &closed(Error::Tls("alert".to_string())),
                true,
                false,
                now,
                later
            ),
            "never on a TLS error"
        );
    }
}
