//! The loopback upstream both contestants resolve against.
//!
//! One [`Responder`] serves UDP, TCP, DoT, DoH over HTTP/2, DoH over HTTP/3
//! and DoQ on ephemeral `127.0.0.1` ports, plus a small stats port that
//! returns the counters as one line of JSON. Answers come from
//! [`crate::wire`], so they are identical for every transport and neither
//! library under test takes part in producing them.
//!
//! # Behavior
//!
//! - **Latency**: every answer is delayed by [`ResponderConfig::latency`]
//!   (a `tokio` timer, so the effective granularity is about 1 ms).
//! - **Pipelining**: on TCP and DoT every frame is answered in its own task
//!   and written back through a channel, so answers may leave out of order
//!   and a pipelining client is never serialised by the responder.
//! - **Dropping**: with [`ResponderConfig::drop_every`] set, every N-th
//!   received query gets no answer at all (all of them for 1). A dropped
//!   query is still counted. This makes retry behavior observable.
//! - **Counters**: per transport, queries received, connections accepted and
//!   TLS or QUIC handshakes completed (TLS: split into full and resumed), so
//!   connection reuse shows up in the results.
//! - **ALPN**: DoT offers none, DoH2 only `h2`, DoH3 only `h3`, DoQ only
//!   `doq`.
//!
//! DoH is POST only (`/dns-query`), which both libraries use here.

use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quinn::crypto::rustls::QuicServerConfig;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;

use crate::Proto;
use crate::fixture::Fixture;
use crate::wire::{self, ResponseConfig, Transport, WireError};

/// Largest datagram or frame the responder reads.
const MAX_MESSAGE: usize = 65_535;
/// Concurrent streams per QUIC connection the responder allows, so the
/// responder is never the stream-limit bottleneck.
const QUIC_STREAMS: u32 = 4_096;

/// How the responder answers.
#[derive(Debug, Clone, Copy)]
pub struct ResponderConfig {
    /// TTL of every record (and the SOA minimum of NXDOMAIN answers).
    pub ttl: u32,
    /// Delay before every answer.
    pub latency: Duration,
    /// Drop every N-th received query without answering; 0 drops none and
    /// 1 drops all.
    pub drop_every: u64,
}

impl Default for ResponderConfig {
    fn default() -> Self {
        Self {
            ttl: 0,
            latency: Duration::ZERO,
            drop_every: 0,
        }
    }
}

/// The ports a [`Responder`] listens on, all on `127.0.0.1`.
#[derive(Debug, Clone, Copy)]
pub struct Ports {
    /// UDP port.
    pub udp: u16,
    /// TCP port.
    pub tcp: u16,
    /// DoT port.
    pub dot: u16,
    /// DoH over HTTP/2 port (TCP).
    pub doh2: u16,
    /// DoH over HTTP/3 port (UDP).
    pub doh3: u16,
    /// DoQ port (UDP).
    pub doq: u16,
    /// Stats port: connecting returns the counters as a line of JSON.
    pub stats: u16,
}

impl Ports {
    /// The port serving `proto`.
    pub fn for_proto(&self, proto: Proto) -> u16 {
        match proto {
            Proto::Udp => self.udp,
            Proto::Tcp => self.tcp,
            Proto::Dot => self.dot,
            Proto::Doh2 => self.doh2,
            Proto::Doh3 => self.doh3,
            Proto::Doq => self.doq,
        }
    }

    /// The ports as a JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "udp": self.udp, "tcp": self.tcp, "dot": self.dot,
            "doh2": self.doh2, "doh3": self.doh3, "doq": self.doq,
            "stats": self.stats,
        })
    }
}

/// Counters for one transport.
#[derive(Debug, Default)]
pub struct ProtoCounters {
    /// Queries received (answered or dropped).
    pub queries: AtomicU64,
    /// Connections accepted (TCP, TLS or QUIC).
    pub connections: AtomicU64,
    /// TLS or QUIC handshakes completed.
    pub handshakes: AtomicU64,
    /// TLS handshakes that resumed a session (a subset of `handshakes`).
    pub resumed: AtomicU64,
}

/// A snapshot of one transport's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtoSnapshot {
    /// Queries received (answered or dropped).
    pub queries: u64,
    /// Connections accepted.
    pub connections: u64,
    /// Handshakes completed.
    pub handshakes: u64,
    /// Handshakes that resumed a session.
    pub resumed: u64,
}

/// The responder's counters.
#[derive(Debug, Default)]
pub struct Counters {
    protos: [ProtoCounters; 6],
    /// UDP answers replaced by a truncated (TC) answer.
    pub tc_replies: AtomicU64,
    /// Queries deliberately left unanswered.
    pub dropped: AtomicU64,
    /// Messages that did not parse as a query.
    pub malformed: AtomicU64,
}

impl Counters {
    /// The counters of `proto`.
    pub fn proto(&self, proto: Proto) -> &ProtoCounters {
        &self.protos[proto.index()]
    }

    /// A snapshot of `proto`'s counters.
    pub fn snapshot(&self, proto: Proto) -> ProtoSnapshot {
        let counters = self.proto(proto);
        ProtoSnapshot {
            queries: counters.queries.load(Ordering::Relaxed),
            connections: counters.connections.load(Ordering::Relaxed),
            handshakes: counters.handshakes.load(Ordering::Relaxed),
            resumed: counters.resumed.load(Ordering::Relaxed),
        }
    }

    /// Queries received over every transport.
    pub fn total_queries(&self) -> u64 {
        Proto::ALL
            .into_iter()
            .map(|proto| self.snapshot(proto).queries)
            .sum()
    }

    /// All counters as a JSON object.
    pub fn to_json(&self) -> Value {
        let mut transports = serde_json::Map::new();
        for proto in Proto::ALL {
            let snapshot = self.snapshot(proto);
            transports.insert(
                proto.as_str().to_string(),
                json!({
                    "queries": snapshot.queries,
                    "connections": snapshot.connections,
                    "handshakes": snapshot.handshakes,
                    "resumed": snapshot.resumed,
                }),
            );
        }
        json!({
            "queries": self.total_queries(),
            "tc_replies": self.tc_replies.load(Ordering::Relaxed),
            "dropped": self.dropped.load(Ordering::Relaxed),
            "malformed": self.malformed.load(Ordering::Relaxed),
            "transports": Value::Object(transports),
        })
    }
}

struct Shared {
    config: ResponderConfig,
    counters: Counters,
    received: AtomicU64,
}

impl Shared {
    /// Counts and answers one query received over `proto`: `Ok(Some)` is
    /// the answer, `Ok(None)` a deliberate drop, `Err` a malformed query.
    async fn reply(&self, proto: Proto, bytes: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
        let counters = self.counters.proto(proto);
        let query = match wire::parse_query(bytes) {
            Ok(query) => query,
            Err(err) => {
                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        };
        counters.queries.fetch_add(1, Ordering::Relaxed);
        let seq = self.received.fetch_add(1, Ordering::Relaxed) + 1;
        let every = self.config.drop_every;
        if every != 0 && seq.is_multiple_of(every) {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        if !self.config.latency.is_zero() {
            tokio::time::sleep(self.config.latency).await;
        }
        let transport = if proto == Proto::Udp {
            Transport::Udp
        } else {
            Transport::Stream
        };
        let response = wire::respond(
            &query,
            ResponseConfig {
                ttl: self.config.ttl,
                transport,
            },
        );
        if proto == Proto::Udp && response.get(2).is_some_and(|flags| flags & 0x02 != 0) {
            self.counters.tc_replies.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Some(response))
    }

    fn handshake_done(&self, proto: Proto, resumed: bool) {
        let counters = self.counters.proto(proto);
        counters.handshakes.fetch_add(1, Ordering::Relaxed);
        if resumed {
            counters.resumed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A running responder. Dropping it (or calling [`shutdown`](Self::shutdown))
/// stops the listeners.
pub struct Responder {
    ports: Ports,
    shared: Arc<Shared>,
    listeners: Vec<AbortHandle>,
}

impl Responder {
    /// Binds every listener on an ephemeral `127.0.0.1` port and starts
    /// serving.
    ///
    /// # Errors
    ///
    /// Returns an error if a socket cannot be bound or the TLS fixture
    /// cannot be turned into server configurations.
    pub async fn start(fixture: &Fixture, config: ResponderConfig) -> io::Result<Responder> {
        let shared = Arc::new(Shared {
            config,
            counters: Counters::default(),
            received: AtomicU64::new(0),
        });
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let mut listeners = Vec::new();

        let udp = Arc::new(UdpSocket::bind(loopback).await?);
        let udp_port = udp.local_addr()?.port();
        for _ in 0..2 {
            let task = tokio::spawn(serve_udp(udp.clone(), shared.clone()));
            listeners.push(task.abort_handle());
        }

        let tcp = TcpListener::bind(loopback).await?;
        let tcp_port = tcp.local_addr()?.port();
        listeners.push(tokio::spawn(serve_tcp(tcp, shared.clone())).abort_handle());

        let dot = TcpListener::bind(loopback).await?;
        let dot_port = dot.local_addr()?.port();
        let acceptor = TlsAcceptor::from(Arc::new(tls(fixture, &[])?));
        listeners.push(tokio::spawn(serve_dot(dot, acceptor, shared.clone())).abort_handle());

        let doh2 = TcpListener::bind(loopback).await?;
        let doh2_port = doh2.local_addr()?.port();
        let acceptor = TlsAcceptor::from(Arc::new(tls(fixture, &[b"h2"])?));
        listeners.push(tokio::spawn(serve_doh2(doh2, acceptor, shared.clone())).abort_handle());

        let doh3 = quic_endpoint(fixture, b"h3", loopback)?;
        let doh3_port = doh3.local_addr()?.port();
        listeners.push(tokio::spawn(serve_doh3(doh3, shared.clone())).abort_handle());

        let doq = quic_endpoint(fixture, b"doq", loopback)?;
        let doq_port = doq.local_addr()?.port();
        listeners.push(tokio::spawn(serve_doq(doq, shared.clone())).abort_handle());

        let stats = TcpListener::bind(loopback).await?;
        let stats_port = stats.local_addr()?.port();
        listeners.push(tokio::spawn(serve_stats(stats, shared.clone())).abort_handle());

        Ok(Responder {
            ports: Ports {
                udp: udp_port,
                tcp: tcp_port,
                dot: dot_port,
                doh2: doh2_port,
                doh3: doh3_port,
                doq: doq_port,
                stats: stats_port,
            },
            shared,
            listeners,
        })
    }

    /// The ports the responder listens on.
    pub fn ports(&self) -> Ports {
        self.ports
    }

    /// The live counters.
    pub fn counters(&self) -> &Counters {
        &self.shared.counters
    }

    /// Stops accepting new connections and datagrams.
    pub fn shutdown(&self) {
        for listener in &self.listeners {
            listener.abort();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn io_err(context: &str, err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {err}"))
}

fn tls(fixture: &Fixture, alpn: &[&[u8]]) -> io::Result<rustls::ServerConfig> {
    fixture
        .server_config(alpn)
        .map_err(|err| io_err("TLS server config", err))
}

fn quic_endpoint(
    fixture: &Fixture,
    alpn: &'static [u8],
    addr: SocketAddr,
) -> io::Result<quinn::Endpoint> {
    let crypto = QuicServerConfig::try_from(tls(fixture, &[alpn])?)
        .map_err(|err| io_err("QUIC server config", err))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(QUIC_STREAMS.into());
    server.transport_config(Arc::new(transport));
    quinn::Endpoint::server(server, addr)
}

// ------------------------------------------------------------------ UDP ---

async fn serve_udp(socket: Arc<UdpSocket>, shared: Arc<Shared>) {
    let mut buf = vec![0_u8; MAX_MESSAGE];
    loop {
        let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        if shared.config.latency.is_zero() {
            if let Ok(Some(answer)) = shared.reply(Proto::Udp, &buf[..len]).await {
                let _ = socket.send_to(&answer, peer).await;
            }
        } else {
            let datagram = buf[..len].to_vec();
            let (socket, shared) = (socket.clone(), shared.clone());
            tokio::spawn(async move {
                if let Ok(Some(answer)) = shared.reply(Proto::Udp, &datagram).await {
                    let _ = socket.send_to(&answer, peer).await;
                }
            });
        }
    }
}

// ---------------------------------------------------------- TCP and DoT ---

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        shared
            .counters
            .proto(Proto::Tcp)
            .connections
            .fetch_add(1, Ordering::Relaxed);
        tokio::spawn(serve_framed(stream, Proto::Tcp, shared.clone()));
    }
}

async fn serve_dot(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        shared
            .counters
            .proto(Proto::Dot)
            .connections
            .fetch_add(1, Ordering::Relaxed);
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            shared.handshake_done(Proto::Dot, is_resumed(tls.get_ref().1.handshake_kind()));
            serve_framed(tls, Proto::Dot, shared).await;
        });
    }
}

fn is_resumed(kind: Option<rustls::HandshakeKind>) -> bool {
    kind == Some(rustls::HandshakeKind::Resumed)
}

/// Serves RFC 1035 §4.2.2 length-prefixed messages on one stream, answering
/// every frame in its own task.
async fn serve_framed<S>(stream: S, proto: Proto, shared: Arc<Shared>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let write = tokio::spawn(async move {
        while let Some(answer) = rx.recv().await {
            let Ok(len) = u16::try_from(answer.len()) else {
                continue;
            };
            let mut frame = Vec::with_capacity(answer.len() + 2);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&answer);
            if writer.write_all(&frame).await.is_err() {
                return;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut len_buf = [0_u8; 2];
    while reader.read_exact(&mut len_buf).await.is_ok() {
        let mut query = vec![0_u8; usize::from(u16::from_be_bytes(len_buf))];
        if reader.read_exact(&mut query).await.is_err() {
            break;
        }
        if shared.config.latency.is_zero() {
            match shared.reply(proto, &query).await {
                Ok(Some(answer)) => {
                    let _ = tx.send(answer);
                }
                Ok(None) => {}
                Err(_) => break,
            }
        } else {
            let (tx, shared) = (tx.clone(), shared.clone());
            tokio::spawn(async move {
                if let Ok(Some(answer)) = shared.reply(proto, &query).await {
                    let _ = tx.send(answer);
                }
            });
        }
    }
    drop(tx);
    let _ = write.await;
}

// ----------------------------------------------------------------- DoH2 ---

async fn serve_doh2(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        let _ = stream.set_nodelay(true);
        shared
            .counters
            .proto(Proto::Doh2)
            .connections
            .fetch_add(1, Ordering::Relaxed);
        let (acceptor, shared) = (acceptor.clone(), shared.clone());
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            shared.handshake_done(Proto::Doh2, is_resumed(tls.get_ref().1.handshake_kind()));
            let service = service_fn(move |request| doh2_request(shared.clone(), request));
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}

async fn doh2_request(
    shared: Arc<Shared>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if request.method() != Method::POST {
        return Ok(status(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Ok(body) = request.into_body().collect().await else {
        return Ok(status(StatusCode::BAD_REQUEST));
    };
    match shared.reply(Proto::Doh2, &body.to_bytes()).await {
        Ok(Some(answer)) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/dns-message")
            .body(Full::new(Bytes::from(answer)))
            .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR))),
        Ok(None) => std::future::pending().await,
        Err(_) => Ok(status(StatusCode::BAD_REQUEST)),
    }
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}

// ----------------------------------------------------------------- DoH3 ---

async fn serve_doh3(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let shared = shared.clone();
        tokio::spawn(async move {
            shared
                .counters
                .proto(Proto::Doh3)
                .connections
                .fetch_add(1, Ordering::Relaxed);
            let Ok(connection) = incoming.await else {
                return;
            };
            shared.handshake_done(Proto::Doh3, false);
            let Ok(mut h3) =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
            else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                tokio::spawn(doh3_request(shared.clone(), resolver));
            }
        });
    }
}

async fn doh3_request(
    shared: Arc<Shared>,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) {
    let Ok((request, mut stream)) = resolver.resolve_request().await else {
        return;
    };
    let mut body = Vec::new();
    while let Ok(Some(mut chunk)) = stream.recv_data().await {
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let taken = part.len();
            chunk.advance(taken);
        }
    }
    let code = if request.method() == Method::POST {
        match shared.reply(Proto::Doh3, &body).await {
            Ok(Some(answer)) => {
                let head = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/dns-message")
                    .body(());
                if let Ok(head) = head
                    && stream.send_response(head).await.is_ok()
                    && stream.send_data(Bytes::from(answer)).await.is_ok()
                {
                    let _ = stream.finish().await;
                }
                return;
            }
            Ok(None) => std::future::pending().await,
            Err(_) => StatusCode::BAD_REQUEST,
        }
    } else {
        StatusCode::METHOD_NOT_ALLOWED
    };
    if let Ok(head) = Response::builder().status(code).body(()) {
        let _ = stream.send_response(head).await;
        let _ = stream.finish().await;
    }
}

// ------------------------------------------------------------------ DoQ ---

async fn serve_doq(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let shared = shared.clone();
        tokio::spawn(async move {
            shared
                .counters
                .proto(Proto::Doq)
                .connections
                .fetch_add(1, Ordering::Relaxed);
            let Ok(connection) = incoming.await else {
                return;
            };
            shared.handshake_done(Proto::Doq, false);
            while let Ok((send, recv)) = connection.accept_bi().await {
                tokio::spawn(doq_stream(shared.clone(), send, recv));
            }
        });
    }
}

/// One DoQ query: a length-prefixed message on a fresh bidirectional stream
/// (RFC 9250 §4.2), answered on the same stream.
async fn doq_stream(shared: Arc<Shared>, mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
    let mut len_buf = [0_u8; 2];
    if recv.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let mut query = vec![0_u8; usize::from(u16::from_be_bytes(len_buf))];
    if recv.read_exact(&mut query).await.is_err() {
        return;
    }
    match shared.reply(Proto::Doq, &query).await {
        Ok(Some(answer)) => {
            let Ok(len) = u16::try_from(answer.len()) else {
                return;
            };
            let mut frame = Vec::with_capacity(answer.len() + 2);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&answer);
            if send.write_all(&frame).await.is_ok() {
                let _ = send.finish();
                // Keep the stream alive until the client has read the answer.
                let _ = send.stopped().await;
            }
        }
        Ok(None) => std::future::pending().await,
        Err(_) => {
            let _ = send.reset(1_u8.into());
        }
    }
}

// ---------------------------------------------------------------- stats ---

async fn serve_stats(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let mut line = shared.counters.to_json().to_string();
        line.push('\n');
        let _ = stream.write_all(line.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// Reads the counters of a running responder from its stats port.
///
/// # Errors
///
/// Returns an error if the connection fails or the reply is not JSON.
pub async fn fetch_stats(port: u16) -> io::Result<Value> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let mut text = String::new();
    stream.read_to_string(&mut text).await?;
    serde_json::from_str(&text).map_err(|err| io_err("stats reply", err))
}
