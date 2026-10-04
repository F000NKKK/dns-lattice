//! Public async upstream DNS backend trait plus baseline UDP and TCP
//! transport implementations.
//!
//! The public, async [`UpstreamBackend`] trait replaces the earlier
//! crate-private synchronous backend seam. It uses `async_trait` because
//! native `async fn` in traits is not
//! `dyn`-safe and this trait is stored as `Box<dyn UpstreamBackend>`), no
//! per-call timeout parameter (each backend's own config owns its
//! timeout(s)), and one dedicated config struct per transport rather than a
//! shared enum.
//!
//! By default [`UdpBackend`] adds no EDNS0/OPT record of its own and falls
//! back to a TCP query to the same server whenever a UDP response arrives
//! with the `TC` (truncated) bit set. It sends the query it is given
//! unchanged, so a forwarded client query keeps the client's OPT record and
//! the upstream may answer with more than 512 bytes; the backend receives
//! any UDP DNS payload up to 65535 bytes.
//! [`UdpBackend::with_edns_udp_payload_size`] opts in to advertising a UDP
//! payload size on queries that carry no OPT record, with a one-shot retry
//! without it when the upstream answers `FORMERR`/`NOTIMP`, and with the OPT
//! record stripped from the returned answer.
//!
//! # Response validation
//!
//! Every built-in backend returns a response only if it answers the query:
//! the `QR` bit is set and the question section matches the query's (name
//! compared case-insensitively, plus type and class). [`UdpBackend`],
//! [`TcpBackend`], and the DoT backend also require the message id to match;
//! the DoH and DoQ backends do not compare it, because RFC 8484 and RFC 9250
//! use id 0 on the wire (the DoQ backend sends its query with id 0); both
//! return the response with the caller's query id. [`UdpBackend`] drops a
//! datagram that does not decode or does not match, and keeps waiting until
//! its timeout expires; the stream-based backends return
//! [`Error::Transport`] for a mismatch, which the resolver fails over on.
//!
//! # DoT, DoH, and DoQ (feature-gated)
//!
//! Three additional backends land in this module, each behind its own
//! default-off Cargo feature so the baseline UDP/TCP build carries no
//! TLS/HTTP/QUIC dependency weight:
//!
//! - `dot` (`#[cfg(feature = "dot")]`): `DotBackend`/`DotBackendConfig`,
//!   DNS-over-TLS (RFC 7858) over `rustls`/`tokio-rustls`.
//! - `doh` (`#[cfg(feature = "doh")]`): `DohBackend`/`DohBackendConfig`,
//!   DNS-over-HTTPS (RFC 8484) over `hyper`/`hyper-rustls`, plus
//!   `Doh3Backend`/`Doh3BackendConfig` for HTTP/3 over QUIC. This feature
//!   deliberately includes the `h3`/`h3-quinn`/`quinn` dependency footprint.
//! - `doq` (`#[cfg(feature = "doq")]`): `DoqBackend`/`DoqBackendConfig`,
//!   DNS-over-QUIC (RFC 9250) over `quinn` (TLS 1.3 embedded in QUIC via
//!   `rustls`). Reuses QUIC connections by default (one bidirectional stream
//!   per query), with the same length-prefixed framing helper as
//!   [`TcpBackend`]/`dot::DotBackend`.
//!
//! `doq` remains independent of `doh`, so an application that needs only
//! DNS-over-QUIC can avoid the HTTP dependencies.
//!
//! All three follow the same `Config` + `Backend` +
//! `#[async_trait] impl UpstreamBackend` pattern as [`UdpBackend`]/
//! [`TcpBackend`]; TLS/HTTP/QUIC-specific fields (SNI server name, TLS
//! client config, HTTP method) live on the new config structs, not the
//! trait.
//!
//! # Connection reuse
//!
//! [`TcpBackend`] and the DoT backend keep a bounded pool of connections to
//! their upstream and pipeline the queries of all callers over them; the DoH
//! backend (HTTP/1.1 and HTTP/2) keeps one HTTP client, multiplexing the
//! queries over one HTTP/2 connection or spreading them over HTTP/1.1
//! connections; the DoQ and DoH3 backends keep a bounded pool of QUIC
//! connections on one shared endpoint and open one stream (one HTTP/3
//! request) per query. See [`PoolConfig`],
//! [`PoolStats`] and each backend's `with_pool` and `pool_stats`. Reuse is on
//! by default and [`PoolConfig::disabled`] turns it off. [`UdpBackend`]
//! (including its TCP fallback for truncated answers) still uses a socket or
//! connection per query.
//!
//! # Runtime requirement
//!
//! Both [`UdpBackend`] and [`TcpBackend`] perform real socket I/O via
//! `tokio` (`tokio::net`, `tokio::time::timeout`) — callers must invoke
//! [`UpstreamBackend::resolve`] (and therefore
//! [`crate::engine::Resolver::resolve`], once a backend of this kind is
//! registered) from inside a `tokio` runtime context.
//!
//! A backend with connection reuse enabled also starts Tokio tasks (a reader
//! and a writer per connection; for DoH, hyper's connection tasks) the first
//! time it needs a connection. Such a
//! backend must stay on the one runtime for its whole life; a program that
//! builds a runtime for each call must switch reuse off with
//! [`PoolConfig::disabled`]. A pool whose runtime has shut down notices that
//! its connections are dead and reconnects on the runtime that calls it next
//! (a query that finds a connection dead is sent again on a fresh one), so
//! it degrades to a connection per runtime rather than failing for good.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Edns, Message, Rcode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

mod pool;
pub use pool::{PoolConfig, PoolStats};

mod stream;
use stream::{StreamOpen, StreamPool};

#[cfg(feature = "dot")]
mod dot;
#[cfg(feature = "dot")]
pub use dot::{DotBackend, DotBackendConfig};

#[cfg(feature = "doh")]
mod doh;
#[cfg(feature = "doh")]
pub use doh::{Doh3Backend, Doh3BackendConfig, DohBackend, DohBackendConfig, DohMethod};

/// Shared QUIC client plumbing: the endpoint-per-backend helper the DoQ and
/// DoH3 backends use.
#[cfg(any(feature = "doq", feature = "doh"))]
mod quic;

#[cfg(feature = "doq")]
mod doq;
/// `pub(crate)` (not exported from the crate root) so `crate::server`'s DoQ
/// listener can reuse the client-side
/// `QuicStream` `AsyncRead`/`AsyncWrite` adapter unchanged, mirroring how
/// `read_framed`/`write_framed` are already shared between `upstream` and
/// `server`.
#[cfg(feature = "doq")]
pub(crate) use doq::QuicStream;
#[cfg(feature = "doq")]
pub use doq::{DoqBackend, DoqBackendConfig};

/// RFC 1035 §4.2.1's 512-byte standard UDP message size: the largest
/// response `crate::server`'s UDP listener sends to a client whose query
/// carries no EDNS(0) OPT record before it truncates the answer and sets
/// `TC=1`. It is also the floor of the UDP limit for EDNS clients: RFC 6891
/// §6.2.5 treats an advertised payload size below 512 as 512.
///
/// This is not the [`UdpBackend`] receive limit. The backend forwards a
/// query unchanged, including any EDNS0 OPT record the original client
/// added, so the upstream may legitimately answer with more than 512 bytes;
/// see [`UDP_RECV_BUFFER_LEN`].
pub(crate) const UDP_MAX_RESPONSE_LEN: usize = 512;

/// The default EDNS(0) UDP payload size, 1232 bytes (the DNS Flag Day 2020
/// value, which avoids IP fragmentation on IPv6 paths with a 1280-byte MTU).
///
/// `crate::server` uses it as the default largest UDP response to an EDNS
/// client and as the payload size its response OPT records advertise;
/// `crate::engine` uses it for the OPT record it attaches when it answers an
/// EDNS query without one (a cache hit or a Fake IP answer).
pub(crate) const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Size of the [`UdpBackend`] receive buffer: the largest DNS message a UDP
/// datagram can carry (the 16-bit UDP length bounds the payload, and a DNS
/// message is addressable up to 65535 bytes). Receiving into a smaller
/// buffer would cut an EDNS0-sized answer, which then fails to decode
/// (Linux) or fails the receive call (Windows).
const UDP_RECV_BUFFER_LEN: usize = 65_535;

/// Whether [`validate_response`] requires the response's message id to
/// equal the query's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdCheck {
    /// The response id must equal the query id (UDP, TCP, DoT).
    Match,
    /// The id is not compared. RFC 8484 §4.1 (DoH) and RFC 9250 §4.2.1
    /// (DoQ) set the message id to 0 on the wire, so a conforming server
    /// may answer with an id that differs from the caller's query id.
    // Only the feature-gated DoH/DoQ backends construct this variant.
    #[cfg_attr(not(any(feature = "doh", feature = "doq")), allow(dead_code))]
    Ignore,
}

/// Checks that `response` answers `query`: the message id matches (unless
/// `id_check` is [`IdCheck::Ignore`]), the `QR` bit is set, and the
/// question section matches the query's in count, order, name (compared
/// case-insensitively), type, and class.
///
/// Shared by every built-in upstream transport so a response for some other
/// query, a reflected query, or a spoofed datagram is never returned to the
/// resolver or cached. A mismatch is reported as [`Error::Transport`], which
/// the resolver treats as retryable and fails over on; the UDP backend
/// instead drops a mismatching datagram and keeps waiting for a valid one
/// until its timeout expires.
pub(crate) fn validate_response(
    query: &Message,
    response: &Message,
    id_check: IdCheck,
) -> Result<()> {
    if id_check == IdCheck::Match && response.header.id != query.header.id {
        return Err(Error::Transport(format!(
            "upstream response id {} does not match query id {}",
            response.header.id, query.header.id
        )));
    }
    if !response.header.qr {
        return Err(Error::Transport(
            "upstream response does not have the QR (response) bit set".to_string(),
        ));
    }
    let questions_match = response.questions.len() == query.questions.len()
        && response
            .questions
            .iter()
            .zip(&query.questions)
            .all(|(answered, asked)| {
                // `Name`'s equality is ASCII case-insensitive.
                answered.name == asked.name
                    && answered.qtype == asked.qtype
                    && answered.qclass == asked.qclass
            });
    if !questions_match {
        return Err(Error::Transport(
            "upstream response question section does not match the query".to_string(),
        ));
    }
    Ok(())
}

/// A public, async, object-safe upstream DNS backend seam: given a query
/// [`Message`], resolve it against this backend and return the answer.
///
/// Implementations own their own
/// timeout/retry policy via their transport-specific config — this trait
/// does not accept a timeout argument.
///
/// Custom transports (e.g. DoT/DoH/DoQ, or any future transport) can
/// implement this trait directly and register with
/// [`crate::engine::ResolverBuilder::backend`] alongside [`UdpBackend`]/
/// [`TcpBackend`].
#[async_trait]
pub trait UpstreamBackend: Send + Sync {
    /// Resolves `query` against this backend, returning the answer
    /// [`Message`] or an [`Error`] if the backend itself fails (transport
    /// error, timeout, malformed response).
    ///
    /// The resolver forwards a fresh answer to the client unchanged, so an
    /// implementation should return it with `query`'s message id, as every
    /// built-in backend does.
    async fn resolve(&self, query: &Message) -> Result<Message>;
}

/// Configuration for [`UdpBackend`].
#[derive(Debug, Clone)]
pub struct UdpBackendConfig {
    /// The upstream DNS server's socket address (IPv4 or IPv6).
    pub server: SocketAddr,
    /// Applied independently to each socket operation (bind, send, recv)
    /// and, on TC-bit fallback, reused as both the TCP connect and read
    /// timeout.
    pub timeout: Duration,
    /// The local address to bind the UDP socket to. `None` binds to the
    /// unspecified address (`0.0.0.0`/`::`, matching `server`'s address
    /// family) on an OS-assigned ephemeral port.
    pub bind_addr: Option<SocketAddr>,
}

/// Baseline UDP upstream backend (RFC 1035 §4.2.1). By default it adds no
/// EDNS0/OPT record of its own (see
/// [`with_edns_udp_payload_size`](Self::with_edns_udp_payload_size) to opt
/// in) and falls back to a TCP query to the same server when a response
/// arrives with the `TC` (truncated) bit set.
///
/// A response of any size up to 65535 bytes is accepted, so an answer
/// larger than 512 bytes to a query that carries an OPT record is returned
/// intact rather than cut off.
pub struct UdpBackend {
    config: UdpBackendConfig,
    /// The UDP payload size to advertise in an OPT record added to a query
    /// that has none, or `None` (the default) to add no OPT record.
    edns_udp_payload_size: Option<u16>,
}

impl UdpBackend {
    /// Builds a UDP backend from `config`. It adds no OPT record of its own.
    pub fn new(config: UdpBackendConfig) -> Self {
        Self {
            config,
            edns_udp_payload_size: None,
        }
    }

    /// Makes the backend advertise EDNS(0) (RFC 6891) to the upstream: a
    /// query that carries no OPT record is sent with one that advertises a UDP
    /// payload size of `size` (raised to at least 512, RFC 6891 §6.2.5), no
    /// options and the DO bit clear, so the upstream may answer over UDP with
    /// more than 512 bytes instead of truncating.
    ///
    /// The advertisement is transparent to the caller:
    ///
    /// - a query that already carries an OPT record, valid or not, is sent
    ///   unchanged, so the client's own advertisement wins;
    /// - if the upstream answers `FORMERR` or `NOTIMP` without an OPT record
    ///   (RFC 6891 §7: it does not implement EDNS), the original query is
    ///   sent once more without an OPT record on the same socket, within the
    ///   same timeout;
    /// - the OPT record is removed from the returned answer, so a client that
    ///   did not use EDNS never sees one;
    /// - an answer whose OPT record carries a nonzero extended RCODE returns
    ///   [`Error::Transport`], because that code cannot be shown to a client
    ///   without EDNS; the resolver treats it as retryable and fails over;
    /// - a truncated (`TC=1`) answer still falls back to TCP, with the
    ///   original query, which carries no OPT record.
    ///
    /// Without this call the backend sends the query unchanged. TCP, DoT, DoH
    /// and DoQ backends never add an OPT record.
    #[must_use]
    pub fn with_edns_udp_payload_size(mut self, size: u16) -> Self {
        self.edns_udp_payload_size = Some(size.max(512));
        self
    }
}

/// Sends `sent` on `socket` and waits until `deadline` for an answer to
/// `sent`.
///
/// A datagram that does not decode, or is not an answer to this query (wrong
/// id, QR=0, or a different question), is dropped and the wait continues, so
/// an off-path spoofed reply cannot displace the real one, cannot end the
/// query early, and cannot extend the wait past the deadline either.
async fn udp_exchange(
    socket: &UdpSocket,
    sent: &Message,
    send_budget: Duration,
    deadline: Instant,
) -> Result<Message> {
    let payload = sent.encode()?;
    send_udp(socket, &payload, send_budget).await?;
    // Heap-allocated: a 64 KiB array would bloat this future's size.
    let mut buf = vec![0u8; UDP_RECV_BUFFER_LEN];
    loop {
        let len = recv_udp(socket, &mut buf, deadline).await?;
        let Ok(response) = Message::decode(&buf[..len]) else {
            continue;
        };
        if validate_response(sent, &response, IdCheck::Match).is_ok() {
            return Ok(response);
        }
    }
}

/// Whether `response` is the answer RFC 6891 §7 says a server without EDNS
/// sends: `FORMERR` or `NOTIMP` and no OPT record.
fn rejects_edns(response: &Message) -> bool {
    matches!(response.header.rcode, Rcode::FormErr | Rcode::NotImp)
        && matches!(response.edns(), Ok(None))
}

#[async_trait]
impl UpstreamBackend for UdpBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let bind_addr = self
            .config
            .bind_addr
            .unwrap_or_else(|| unspecified_like(self.config.server));

        let socket = bind_udp(bind_addr, self.config.timeout).await?;
        connect_udp(&socket, self.config.server, self.config.timeout).await?;

        // With the opt-in configured, a query without an OPT record is sent
        // with one; a query that has any OPT record (even a malformed one)
        // is forwarded unchanged.
        let with_opt = match (self.edns_udp_payload_size, query.edns()) {
            (Some(size), Ok(None)) => {
                let mut copy = query.clone();
                copy.set_edns(Some(Edns::new(size)));
                Some(copy)
            }
            _ => None,
        };

        // One deadline bounds the whole receive phase, including the
        // FORMERR/NOTIMP retry.
        let deadline = Instant::now() + self.config.timeout;
        let response = match &with_opt {
            Some(sent) => {
                let first = udp_exchange(&socket, sent, self.config.timeout, deadline).await?;
                if rejects_edns(&first) {
                    // The upstream does not implement EDNS: retry once with
                    // the original, OPT-less query (RFC 6891 §7).
                    udp_exchange(&socket, query, self.config.timeout, deadline).await?
                } else {
                    // The advertisement was accepted, so the answer's OPT
                    // record is ours to strip.
                    let mut answer = first;
                    if let Ok(Some(edns)) = answer.edns()
                        && edns.extended_rcode() != 0
                        && !answer.header.truncated
                    {
                        return Err(Error::Transport(format!(
                            "upstream answered with extended RCODE {} that a query without EDNS cannot carry",
                            edns.extended_rcode()
                        )));
                    }
                    answer.set_edns(None);
                    answer
                }
            }
            None => udp_exchange(&socket, query, self.config.timeout, deadline).await?,
        };

        if response.header.truncated {
            return tcp_query(
                self.config.server,
                self.config.timeout,
                self.config.timeout,
                query,
            )
            .await;
        }

        Ok(response)
    }
}

/// Configuration for [`TcpBackend`].
#[derive(Debug, Clone)]
pub struct TcpBackendConfig {
    /// The upstream DNS server's socket address (IPv4 or IPv6).
    pub server: SocketAddr,
    /// Bounds the TCP connect phase.
    pub connect_timeout: Duration,
    /// Bounds each subsequent write/read on the already-connected stream.
    pub read_timeout: Duration,
}

/// Baseline TCP upstream backend (RFC 1035 §4.2.2: 2-byte big-endian length
/// prefix followed by the encoded message).
///
/// # Connection reuse
///
/// By default the backend keeps a small pool of connections to the upstream
/// and sends the queries of all callers over them, several at a time and
/// without waiting for each answer (RFC 7766 §6.2.1.1 pipelining). The
/// upstream may answer in any order; every caller gets the answer to its own
/// question, with its own message id. A [`PoolConfig`] passed to
/// [`with_pool`](Self::with_pool) sets the bounds (connections, queries per
/// connection, idle timeout, maximum lifetime), and
/// [`pool_stats`](Self::pool_stats) reports what the pool did.
/// [`PoolConfig::disabled`] restores one connection per query.
///
/// A query is sent again, once, on a fresh connection when the pooled
/// connection it used had already answered a query and then failed at the
/// connection level (the server closed or reset it) and the query's opcode
/// is `QUERY`. Timeouts, validation mismatches and undecodable answers are
/// never retried, and the error classes are the ones the backend always
/// returned.
///
/// A response is accepted only for a query that is waiting for it. A frame
/// that matches no waiting query (for example a response with a different
/// message id) is dropped, so such a reply is no longer reported as
/// [`Error::Transport`] but leaves the query to time out; a response that
/// matches a waiting query but not its question is reported as
/// [`Error::Transport`], as before. An upstream that sends more than 16
/// stray frames in a row has its connection closed.
///
/// With reuse enabled the backend starts Tokio tasks and keeps sockets open
/// between queries, so it must be used from one Tokio runtime for its whole
/// life (a pattern that builds a runtime per call must use
/// [`PoolConfig::disabled`]); dropping the backend closes its connections
/// and ends its tasks. One connection then carries the queries of many
/// clients, which the upstream can correlate more easily than one
/// connection per query.
pub struct TcpBackend {
    config: TcpBackendConfig,
    pool: Option<StreamPool<TcpOpen>>,
}

impl TcpBackend {
    /// Builds a TCP backend from `config` with connection reuse on
    /// ([`PoolConfig::new`]).
    pub fn new(config: TcpBackendConfig) -> Self {
        Self { config, pool: None }.with_pool(PoolConfig::new())
    }

    /// Replaces the connection-reuse policy. [`PoolConfig::disabled`] makes
    /// every query use a connection of its own, as before connection reuse
    /// existed.
    #[must_use]
    pub fn with_pool(mut self, pool: PoolConfig) -> Self {
        self.pool = pool.is_enabled().then(|| {
            let read = self.config.read_timeout;
            StreamPool::new(
                pool,
                TcpOpen {
                    server: self.config.server,
                    connect_timeout: self.config.connect_timeout,
                },
                read,
                // The longest one call could take without reuse: connect,
                // write, read.
                self.config
                    .connect_timeout
                    .saturating_add(read.saturating_mul(2)),
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

/// Opens the plain TCP connections of a [`TcpBackend`] pool.
struct TcpOpen {
    server: SocketAddr,
    connect_timeout: Duration,
}

impl StreamOpen for TcpOpen {
    type Stream = TcpStream;

    async fn open(&self) -> Result<TcpStream> {
        let stream = timeout(self.connect_timeout, TcpStream::connect(self.server))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|err| Error::Transport(err.to_string()))?;
        // Pipelined queries are small and latency sensitive: do not let
        // Nagle's algorithm hold a query back until the previous one is
        // acknowledged.
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

#[async_trait]
impl UpstreamBackend for TcpBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        match &self.pool {
            Some(pool) => pool.query(query).await,
            None => {
                tcp_query(
                    self.config.server,
                    self.config.connect_timeout,
                    self.config.read_timeout,
                    query,
                )
                .await
            }
        }
    }
}

/// Returns the unspecified address (`0.0.0.0`/`::`) matching `addr`'s
/// address family, on port `0` (OS-assigned ephemeral port).
fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn bind_udp(bind_addr: SocketAddr, budget: Duration) -> Result<UdpSocket> {
    timeout(budget, UdpSocket::bind(bind_addr))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))
}

async fn connect_udp(socket: &UdpSocket, server: SocketAddr, budget: Duration) -> Result<()> {
    timeout(budget, socket.connect(server))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))
}

async fn send_udp(socket: &UdpSocket, payload: &[u8], budget: Duration) -> Result<()> {
    timeout(budget, socket.send(payload))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
    Ok(())
}

async fn recv_udp(socket: &UdpSocket, buf: &mut [u8], deadline: Instant) -> Result<usize> {
    timeout_at(deadline, socket.recv(buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))
}

/// Sends `query` over a fresh TCP connection to `server` (RFC 1035
/// §4.2.2's 2-byte length-prefixed framing) and returns the decoded
/// response. Shared by [`TcpBackend::resolve`] and [`UdpBackend`]'s
/// TC-bit fallback.
async fn tcp_query(
    server: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
    query: &Message,
) -> Result<Message> {
    let mut stream = timeout(connect_timeout, TcpStream::connect(server))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;

    framed_query(&mut stream, read_timeout, query, IdCheck::Match).await
}

/// Sends `query` over an already-established, ordered byte stream using
/// RFC 1035 §4.2.2's 2-byte big-endian length-prefixed framing, and
/// returns the decoded response. Shared by [`tcp_query`] (plaintext TCP)
/// and, behind the `dot`/`doq` features, `dot::DotBackend` (the same
/// framing over an established TLS stream) and `doq::DoqBackend` (one
/// bidirectional QUIC stream).
///
/// The decoded response is checked with [`validate_response`] using
/// `id_check`; a mismatch is returned as [`Error::Transport`] so the
/// resolver fails over to the next backend.
///
/// Implemented in terms of [`write_framed`] and [`read_framed`] — this
/// one-shot write-then-read shape stays as the
/// client-role helper; `crate::server`'s read-many/respond-many TCP loop
/// calls the two halves directly instead of this function.
pub(crate) async fn framed_query<S>(
    stream: &mut S,
    budget: Duration,
    query: &Message,
    id_check: IdCheck,
) -> Result<Message>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_framed(stream, budget, query).await?;
    let response = read_framed(stream, budget).await?;
    validate_response(query, &response, id_check)?;
    Ok(response)
}

/// Writes `message` to `stream` using RFC 1035 §4.2.2's 2-byte big-endian
/// length-prefixed framing (a 2-byte length prefix followed by the encoded
/// message), bounded by `budget`.
///
/// One half of the `framed_query` split:
/// shared by [`framed_query`] (client-side, one write per call) and
/// `crate::server`'s TCP listener (one write per response, potentially many
/// per connection).
pub(crate) async fn write_framed<S>(
    stream: &mut S,
    budget: Duration,
    message: &Message,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let payload = message.encode()?;
    let len: u16 = payload
        .len()
        .try_into()
        .map_err(|_| Error::MessageTooLong)?;

    let mut framed = Vec::with_capacity(payload.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);

    timeout(budget, stream.write_all(&framed))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
    Ok(())
}

/// Reads one RFC 1035 §4.2.2 length-prefixed message from `stream`, bounded
/// by `budget`.
///
/// One half of the `framed_query` split:
/// shared by [`framed_query`] (client-side, one read per call) and
/// `crate::server`'s TCP listener (one read per inbound request,
/// potentially many per connection). Returns [`Error::Timeout`] if the
/// length prefix or payload is not fully read within `budget` — in
/// particular, a peer that never sends anything (e.g. an idle/closed
/// connection) surfaces as this same error rather than hanging, since
/// `read_exact` on a cleanly closed stream returns an I/O error mapped to
/// [`Error::Transport`] rather than `Ok`.
pub(crate) async fn read_framed<S>(stream: &mut S, budget: Duration) -> Result<Message>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    timeout(budget, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; response_len];
    timeout(budget, stream.read_exact(&mut response_buf))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|err| Error::Transport(err.to_string()))?;

    Message::decode(&response_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{
        Class, Header, Name, Opcode, Question, RData, Rcode, RecordType, ResourceRecord,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

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

    /// Binds a UDP socket and a TCP listener on the same loopback port. An
    /// ephemeral UDP port can already be taken by a TCP socket of another
    /// test, so the pair is retried on a fresh port.
    async fn bind_udp_tcp_pair() -> (UdpSocket, TcpListener) {
        for _ in 0..50 {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                return (udp, tcp);
            }
        }
        panic!("no free loopback port for a UDP/TCP pair");
    }

    #[tokio::test]
    async fn udp_backend_resolves_against_a_loopback_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let query = Message::decode(&buf[..len]).unwrap();
            let response = answer_for("example.com", query.header.id);
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("udp backend resolves");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn udp_backend_falls_back_to_tcp_on_truncated_response() {
        let (udp_server, tcp_listener) = bind_udp_tcp_pair().await;
        let udp_addr = udp_server.local_addr().unwrap();

        let udp_responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = udp_server.recv_from(&mut buf).await.unwrap();
            let query = Message::decode(&buf[..len]).unwrap();
            let mut truncated = answer_for("example.com", query.header.id);
            truncated.header.truncated = true;
            udp_server
                .send_to(&truncated.encode().unwrap(), from)
                .await
                .unwrap();
        });

        let tcp_responder = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();

            let response = answer_for("example.com", query.header.id);
            let bytes = response.encode().unwrap();
            let framed_len: u16 = bytes.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&framed_len.to_be_bytes());
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.unwrap();
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: udp_addr,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("udp backend falls back to tcp on truncation");
        assert!(!answer.header.truncated);
        udp_responder.await.unwrap();
        tcp_responder.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_backend_resolves_against_a_loopback_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();

            let response = answer_for("example.com", query.header.id);
            let bytes = response.encode().unwrap();
            let framed_len: u16 = bytes.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&framed_len.to_be_bytes());
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.unwrap();
        });

        let backend = TcpBackend::new(TcpBackendConfig {
            server: addr,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("tcp backend resolves");
        assert!(answer.header.qr);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn udp_backend_times_out_when_server_never_responds() {
        // Bind a server socket but never read/respond from it, so the
        // client-side recv never completes; a short timeout must still
        // return promptly instead of hanging deterministically-run tests.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_millis(50),
            bind_addr: None,
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("no response within the timeout budget");
        assert_eq!(err, Error::Timeout);
    }

    #[tokio::test]
    async fn tcp_backend_returns_transport_when_peer_closes_connection() {
        // A controlled loopback peer accepts exactly one TCP connection and
        // closes it without speaking DNS. This avoids relying on the OS-
        // specific behavior of connecting TCP to a UDP-bound port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let backend = TcpBackend::new(TcpBackendConfig {
            server: addr,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a peer that closes before a DNS response is transport failure");
        assert!(matches!(err, Error::Transport(_)));
        responder.await.unwrap();
    }

    #[test]
    fn validate_response_accepts_a_matching_answer() {
        let query = query_for("example.com");
        let answer = answer_for("example.com", query.header.id);
        assert_eq!(validate_response(&query, &answer, IdCheck::Match), Ok(()));
    }

    #[test]
    fn validate_response_matches_the_question_name_case_insensitively() {
        let query = query_for("ExAmPlE.CoM");
        let answer = answer_for("example.com", query.header.id);
        assert_eq!(validate_response(&query, &answer, IdCheck::Match), Ok(()));
        let query = query_for("example.com");
        let answer = answer_for("EXAMPLE.COM", query.header.id);
        assert_eq!(validate_response(&query, &answer, IdCheck::Match), Ok(()));
    }

    #[test]
    fn validate_response_rejects_a_wrong_id_unless_ignored() {
        let query = query_for("example.com");
        let answer = answer_for("example.com", query.header.id.wrapping_add(1));
        assert!(matches!(
            validate_response(&query, &answer, IdCheck::Match),
            Err(Error::Transport(_))
        ));
        // DoH/DoQ: RFC 8484/9250 put id 0 on the wire.
        let answer = answer_for("example.com", 0);
        assert_eq!(validate_response(&query, &answer, IdCheck::Ignore), Ok(()));
    }

    #[test]
    fn validate_response_rejects_qr_zero_even_when_the_id_is_ignored() {
        let query = query_for("example.com");
        for id_check in [IdCheck::Match, IdCheck::Ignore] {
            assert!(matches!(
                validate_response(&query, &query, id_check),
                Err(Error::Transport(_))
            ));
        }
    }

    #[test]
    fn validate_response_rejects_a_different_question() {
        let query = query_for("example.com");
        let id = query.header.id;

        let other_name = answer_for("example.org", id);
        let mut other_type = answer_for("example.com", id);
        other_type.questions[0].qtype = RecordType::Aaaa;
        let mut other_class = answer_for("example.com", id);
        other_class.questions[0].qclass = Class::Ch;
        let mut no_question = answer_for("example.com", id);
        no_question.questions.clear();
        let mut extra_question = answer_for("example.com", id);
        extra_question
            .questions
            .push(extra_question.questions[0].clone());

        for answer in [
            other_name,
            other_type,
            other_class,
            no_question,
            extra_question,
        ] {
            for id_check in [IdCheck::Match, IdCheck::Ignore] {
                assert!(
                    matches!(
                        validate_response(&query, &answer, id_check),
                        Err(Error::Transport(_))
                    ),
                    "{answer:?} must not be accepted for {query:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn udp_backend_drops_mismatching_datagrams_and_accepts_the_valid_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let query = Message::decode(&buf[..len]).unwrap();
            let id = query.header.id;

            let wrong_id = answer_for("example.com", id.wrapping_add(1));
            let mut not_a_response = answer_for("example.com", id);
            not_a_response.header.qr = false;
            let wrong_question = answer_for("example.org", id);
            let mut wrong_type = answer_for("example.com", id);
            wrong_type.questions[0].qtype = RecordType::Aaaa;
            // The valid answer echoes the name in a different case.
            let mut valid = answer_for("EXAMPLE.com", id);
            valid.header.rcode = Rcode::NxDomain;

            // A datagram that does not even decode (shorter than a header)
            // is dropped too, rather than ending the query.
            server.send_to(&[0xff; 3], from).await.unwrap();
            for response in [wrong_id, not_a_response, wrong_question, wrong_type, valid] {
                server
                    .send_to(&response.encode().unwrap(), from)
                    .await
                    .unwrap();
            }
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        });

        let answer = backend
            .resolve(&query_for("Example.COM"))
            .await
            .expect("the valid answer after the mismatching datagrams is accepted");
        assert!(answer.header.qr);
        assert_eq!(answer.header.id, 11);
        assert_eq!(answer.header.rcode, Rcode::NxDomain);
        responder.await.unwrap();
    }

    /// An EDNS0 OPT pseudo-record (RFC 6891 §6.1.2) advertising a 4096-byte
    /// UDP payload, carried as an opaque record since the model has no
    /// EDNS0 type.
    fn opt_record() -> ResourceRecord {
        ResourceRecord {
            name: Name::root(),
            rtype: RecordType::Other(41),
            class: Class::Other(4096),
            ttl: 0,
            rdata: RData::Unknown {
                rtype: 41,
                data: vec![],
            },
        }
    }

    /// Sends `query` to a loopback UDP responder that answers with 100 A
    /// records (well over 512 bytes) and asserts the backend returns the
    /// whole answer.
    async fn assert_udp_backend_receives_a_large_answer(query: Message) {
        const ANSWERS: usize = 100;
        let expect_opt = !query.additionals.is_empty();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let query = Message::decode(&buf[..len]).unwrap();
            // The backend forwards the query unchanged, OPT included.
            assert_eq!(!query.additionals.is_empty(), expect_opt);

            let mut response = answer_for("example.com", query.header.id);
            response.answers = (0..ANSWERS)
                .map(|i| ResourceRecord {
                    name: Name::from_ascii("example.com").unwrap(),
                    rtype: RecordType::A,
                    class: Class::In,
                    ttl: 300,
                    rdata: RData::A(Ipv4Addr::new(192, 0, 2, i as u8)),
                })
                .collect();
            response.additionals = query.additionals.clone();
            let bytes = response.encode().unwrap();
            assert!(bytes.len() > UDP_MAX_RESPONSE_LEN, "{} bytes", bytes.len());
            server.send_to(&bytes, from).await.unwrap();
            bytes.len()
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        });

        let answer = backend
            .resolve(&query)
            .await
            .expect("an answer larger than 512 bytes decodes intact");
        let sent_len = responder.await.unwrap();
        assert!(!answer.header.truncated);
        assert_eq!(answer.answers.len(), ANSWERS);
        for (i, record) in answer.answers.iter().enumerate() {
            assert_eq!(record.rdata, RData::A(Ipv4Addr::new(192, 0, 2, i as u8)));
        }
        assert_eq!(answer.additionals, query.additionals);
        assert_eq!(answer.encode().unwrap().len(), sent_len);
    }

    #[tokio::test]
    async fn udp_backend_receives_an_answer_larger_than_512_bytes_for_an_edns_query() {
        let mut query = query_for("example.com");
        query.additionals.push(opt_record());
        assert_udp_backend_receives_a_large_answer(query).await;
    }

    #[tokio::test]
    async fn udp_backend_receives_an_answer_larger_than_512_bytes_without_edns() {
        assert_udp_backend_receives_a_large_answer(query_for("example.com")).await;
    }

    #[tokio::test]
    async fn udp_backend_times_out_when_only_mismatching_datagrams_arrive() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, from) = server.recv_from(&mut buf).await.unwrap();
            let query = Message::decode(&buf[..len]).unwrap();
            let spoofed = answer_for("example.com", query.header.id.wrapping_add(1));
            server
                .send_to(&spoofed.encode().unwrap(), from)
                .await
                .unwrap();
            // An undecodable datagram does not end the query early either.
            server.send_to(&[0xff; 3], from).await.unwrap();
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_millis(200),
            bind_addr: None,
        });

        let err = backend
            .resolve(&query_for("example.com"))
            .await
            .expect_err("a mismatching datagram is never returned");
        assert_eq!(err, Error::Timeout);
        responder.await.unwrap();
    }

    /// Receives one datagram on `server` and returns the decoded query with
    /// the sender.
    async fn recv_query(server: &UdpSocket) -> (Message, SocketAddr) {
        let mut buf = vec![0u8; 65_535];
        let (len, from) = server.recv_from(&mut buf).await.unwrap();
        (Message::decode(&buf[..len]).unwrap(), from)
    }

    fn edns_backend(server: SocketAddr, size: u16) -> UdpBackend {
        UdpBackend::new(UdpBackendConfig {
            server,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        })
        .with_edns_udp_payload_size(size)
    }

    #[tokio::test]
    async fn udp_backend_without_the_opt_in_sends_no_opt() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let response = answer_for("example.com", query.header.id);
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
            query.edns().unwrap()
        });

        let backend = UdpBackend::new(UdpBackendConfig {
            server: server_addr,
            timeout: Duration::from_secs(2),
            bind_addr: None,
        });
        backend.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(responder.await.unwrap(), None);
    }

    #[tokio::test]
    async fn udp_backend_adds_an_opt_and_strips_it_from_the_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let mut response = answer_for("example.com", query.header.id);
            let mut upstream_opt = Edns::new(4096);
            upstream_opt.set_dnssec_ok(true);
            response.set_edns(Some(upstream_opt));
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
            query.edns().unwrap()
        });

        // Sizes below 512 are raised to 512.
        let answer = edns_backend(server_addr, 100)
            .resolve(&query_for("example.com"))
            .await
            .expect("the answer is returned");
        let sent = responder.await.unwrap().expect("the query carried an OPT");
        assert_eq!(sent, Edns::new(512));
        assert_eq!(answer.edns().unwrap(), None);
        assert!(answer.additionals.is_empty());

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let response = answer_for("example.com", query.header.id);
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
            query.edns().unwrap()
        });
        edns_backend(server_addr, 1400)
            .resolve(&query_for("example.com"))
            .await
            .unwrap();
        assert_eq!(responder.await.unwrap(), Some(Edns::new(1400)));
    }

    #[tokio::test]
    async fn udp_backend_forwards_a_client_opt_unchanged() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let mut response = answer_for("example.com", query.header.id);
            response.additionals = query.additionals.clone();
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
            query
        });

        let mut client_opt = Edns::new(4096);
        client_opt.set_dnssec_ok(true);
        let mut query = query_for("example.com");
        query.set_edns(Some(client_opt.clone()));

        let answer = edns_backend(server_addr, 1232)
            .resolve(&query)
            .await
            .unwrap();
        let received = responder.await.unwrap();
        assert_eq!(received.additionals, query.additionals);
        assert_eq!(received.edns().unwrap(), Some(client_opt.clone()));
        // The client's own OPT is not ours to strip.
        assert_eq!(answer.edns().unwrap(), Some(client_opt));
    }

    #[tokio::test]
    async fn udp_backend_retries_once_without_the_opt_after_formerr_or_notimp() {
        for rcode in [Rcode::FormErr, Rcode::NotImp] {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_addr = server.local_addr().unwrap();
            let responder = tokio::spawn(async move {
                let mut seen = Vec::new();
                // A non-EDNS upstream rejects the OPT and answers a plain
                // query.
                let (first, from) = recv_query(&server).await;
                let mut rejection = answer_for("example.com", first.header.id);
                rejection.header.rcode = rcode;
                server
                    .send_to(&rejection.encode().unwrap(), from)
                    .await
                    .unwrap();
                seen.push(first.edns().unwrap().is_some());
                let (second, from) = recv_query(&server).await;
                let response = answer_for("example.com", second.header.id);
                server
                    .send_to(&response.encode().unwrap(), from)
                    .await
                    .unwrap();
                seen.push(second.edns().unwrap().is_some());
                seen
            });

            let answer = edns_backend(server_addr, 1232)
                .resolve(&query_for("example.com"))
                .await
                .expect("the OPT-less retry is answered");
            assert_eq!(answer.header.rcode, Rcode::NoError, "{rcode:?}");
            assert_eq!(answer.edns().unwrap(), None);
            // Exactly two queries: with the OPT, then without.
            assert_eq!(responder.await.unwrap(), vec![true, false], "{rcode:?}");
        }
    }

    #[tokio::test]
    async fn udp_backend_formerr_with_an_opt_is_returned_without_a_retry() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let mut response = answer_for("example.com", query.header.id);
            response.header.rcode = Rcode::FormErr;
            response.set_edns(Some(Edns::new(1232)));
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
            // No second query may arrive.
            tokio::time::timeout(Duration::from_millis(200), recv_query(&server))
                .await
                .is_err()
        });

        let answer = edns_backend(server_addr, 1232)
            .resolve(&query_for("example.com"))
            .await
            .unwrap();
        assert_eq!(answer.header.rcode, Rcode::FormErr);
        assert_eq!(answer.edns().unwrap(), None);
        assert!(
            responder.await.unwrap(),
            "no retry for an EDNS-aware FORMERR"
        );
    }

    #[tokio::test]
    async fn udp_backend_turns_an_upstream_extended_rcode_into_a_transport_error() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (query, from) = recv_query(&server).await;
            let mut response = answer_for("example.com", query.header.id);
            let mut opt = Edns::new(1232);
            opt.set_extended_rcode(1);
            response.set_edns(Some(opt));
            server
                .send_to(&response.encode().unwrap(), from)
                .await
                .unwrap();
        });

        let err = edns_backend(server_addr, 1232)
            .resolve(&query_for("example.com"))
            .await
            .expect_err("an extended RCODE cannot be shown to a non-EDNS client");
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn udp_backend_falls_back_to_tcp_without_the_opt_when_truncated() {
        let (udp_server, tcp_listener) = bind_udp_tcp_pair().await;
        let addr = udp_server.local_addr().unwrap();

        let udp_responder = tokio::spawn(async move {
            let (query, from) = recv_query(&udp_server).await;
            let mut truncated = answer_for("example.com", query.header.id);
            truncated.header.truncated = true;
            truncated.set_edns(Some(Edns::new(1232)));
            udp_server
                .send_to(&truncated.encode().unwrap(), from)
                .await
                .unwrap();
            query.edns().unwrap().is_some()
        });
        let tcp_responder = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let mut payload = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let query = Message::decode(&payload).unwrap();
            let bytes = answer_for("example.com", query.header.id).encode().unwrap();
            let framed_len: u16 = bytes.len().try_into().unwrap();
            stream.write_all(&framed_len.to_be_bytes()).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            query.edns().unwrap()
        });

        let answer = edns_backend(addr, 1232)
            .resolve(&query_for("example.com"))
            .await
            .unwrap();
        assert!(!answer.header.truncated);
        assert!(udp_responder.await.unwrap(), "the UDP query carried an OPT");
        assert_eq!(
            tcp_responder.await.unwrap(),
            None,
            "the TCP query is the original"
        );
    }

    /// Accepts one TCP connection, reads one framed query, and answers it
    /// with `respond(query)`.
    async fn serve_one_tcp_response(
        listener: TcpListener,
        respond: impl FnOnce(&Message) -> Message,
    ) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        let query = Message::decode(&payload).unwrap();

        let bytes = respond(&query).encode().unwrap();
        let framed_len: u16 = bytes.len().try_into().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&framed_len.to_be_bytes());
        framed.extend_from_slice(&bytes);
        stream.write_all(&framed).await.unwrap();
        // Keep the connection open until the client closes it, so a pooled
        // client's behaviour does not depend on the server hanging up.
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest).await;
    }

    /// The backend must reject a response that does not answer the query.
    /// Without pooling the id is compared against the one sent, so a wrong
    /// id is a transport error. A pooled connection matches answers by the
    /// id it assigned itself, so an answer carrying an unknown id is an
    /// unsolicited frame that is dropped, and the query times out.
    #[tokio::test]
    async fn tcp_backend_rejects_mismatching_responses() {
        type Respond = fn(&Message) -> Message;
        let responders: [(&str, Respond, bool); 3] = [
            (
                "wrong id",
                |query| answer_for("example.com", query.header.id.wrapping_add(1)),
                true,
            ),
            (
                "qr zero",
                |query| {
                    let mut reply = answer_for("example.com", query.header.id);
                    reply.header.qr = false;
                    reply
                },
                false,
            ),
            (
                "wrong question",
                |query| answer_for("example.org", query.header.id),
                false,
            ),
        ];

        for pool in [PoolConfig::disabled(), PoolConfig::new()] {
            let pooled = pool.is_enabled();
            for (case, respond, id_case) in responders {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let responder = tokio::spawn(serve_one_tcp_response(listener, respond));

                let backend = TcpBackend::new(TcpBackendConfig {
                    server: addr,
                    connect_timeout: Duration::from_secs(2),
                    read_timeout: Duration::from_millis(400),
                })
                .with_pool(pool.clone());

                let err = backend
                    .resolve(&query_for("example.com"))
                    .await
                    .expect_err("a mismatching tcp response is rejected");
                if pooled && id_case {
                    assert!(matches!(err, Error::Timeout), "{case}: {err:?}");
                } else {
                    assert!(matches!(err, Error::Transport(_)), "{case}: {err:?}");
                }
                drop(backend);
                responder.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn tcp_backend_accepts_a_case_different_question_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = tokio::spawn(serve_one_tcp_response(listener, |query| {
            answer_for("EXAMPLE.COM", query.header.id)
        }));

        let backend = TcpBackend::new(TcpBackendConfig {
            server: addr,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
        });

        let answer = backend
            .resolve(&query_for("example.com"))
            .await
            .expect("the name comparison is case-insensitive");
        assert!(answer.header.qr);
        drop(backend);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn resolver_fails_over_when_an_upstream_answers_the_wrong_question() {
        use crate::engine::Resolver;
        use dns_lattice_model::{SplitDnsPolicy, UpstreamGroupId};

        let bad = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad.local_addr().unwrap();
        let bad_responder = tokio::spawn(serve_one_tcp_response(bad, |query| {
            answer_for("example.org", query.header.id)
        }));
        let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good.local_addr().unwrap();
        let good_responder = tokio::spawn(serve_one_tcp_response(good, |query| {
            answer_for("example.com", query.header.id)
        }));

        let tcp = |server| {
            TcpBackend::new(TcpBackendConfig {
                server,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
            })
        };
        let group = UpstreamGroupId::new("default");
        let policy = SplitDnsPolicy::builder()
            .default_group(group.clone())
            .build();
        let resolver = Resolver::builder(policy)
            .backend(group.clone(), tcp(bad_addr))
            .backend(group, tcp(good_addr))
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("the resolver fails over to the matching upstream");
        assert_eq!(answer.questions, query_for("example.com").questions);
        drop(resolver);
        bad_responder.await.unwrap();
        good_responder.await.unwrap();
    }

    // ---- pooled TCP over loopback ---------------------------------------------

    /// A loopback TCP DNS server that counts accepted connections. Each
    /// connection answers every query immediately and, when
    /// `answers_per_connection` is set, hangs up after that many answers.
    struct CountingServer {
        addr: SocketAddr,
        accepted: Arc<AtomicUsize>,
    }

    impl CountingServer {
        async fn start(answers_per_connection: Option<usize>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&accepted);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve_connection(stream, answers_per_connection));
                }
            });
            CountingServer { addr, accepted }
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }

        fn backend(&self) -> TcpBackend {
            TcpBackend::new(TcpBackendConfig {
                server: self.addr,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(5),
            })
        }
    }

    async fn serve_connection(mut stream: TcpStream, limit: Option<usize>) {
        let mut served = 0usize;
        loop {
            if limit.is_some_and(|n| served >= n) {
                return;
            }
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return;
            }
            let mut payload = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            let query = Message::decode(&payload).unwrap();
            let mut response = query.clone();
            response.header.qr = true;
            let bytes = response.encode().unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            if stream.write_all(&framed).await.is_err() {
                return;
            }
            served += 1;
        }
    }

    #[tokio::test]
    async fn pooled_tcp_backend_reuses_one_connection_for_sequential_queries() {
        let server = CountingServer::start(None).await;
        let backend = server.backend();
        for i in 0..5 {
            let name = format!("n{i}.example.com");
            let answer = backend.resolve(&query_for(&name)).await.unwrap();
            assert_eq!(answer.questions, query_for(&name).questions);
            assert_eq!(answer.header.id, 11);
        }
        assert_eq!(server.accepted(), 1);
        let stats = backend.pool_stats();
        assert_eq!(stats.queries(), 5);
        assert_eq!(stats.reused_queries(), 4);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_concurrent_tcp_queries_share_a_few_connections() {
        let server = CountingServer::start(None).await;
        let backend = Arc::new(
            server
                .backend()
                .with_pool(PoolConfig::new().max_connections(2)),
        );
        let calls: Vec<_> = (0..200)
            .map(|i| {
                let backend = Arc::clone(&backend);
                tokio::spawn(async move {
                    let name = format!("c{i}.example.com");
                    let answer = backend.resolve(&query_for(&name)).await.unwrap();
                    assert_eq!(answer.questions, query_for(&name).questions);
                    assert_eq!(answer.header.id, 11);
                })
            })
            .collect();
        for call in calls {
            call.await.unwrap();
        }
        assert!(server.accepted() <= 2, "{} connections", server.accepted());
        assert_eq!(backend.pool_stats().queries(), 200);
    }

    #[tokio::test]
    async fn a_disabled_pool_opens_one_connection_per_query() {
        let server = CountingServer::start(None).await;
        let backend = server.backend().with_pool(PoolConfig::disabled());
        for i in 0..3 {
            backend
                .resolve(&query_for(&format!("d{i}.example.com")))
                .await
                .unwrap();
        }
        assert_eq!(server.accepted(), 3);
        assert_eq!(backend.pool_stats(), PoolStats::default());
    }

    #[tokio::test]
    async fn tcp_backend_reconnects_after_the_server_closes_after_a_few_answers() {
        let server = CountingServer::start(Some(2)).await;
        let backend = server.backend();
        for i in 0..6 {
            let name = format!("r{i}.example.com");
            let answer = backend.resolve(&query_for(&name)).await.unwrap();
            assert_eq!(answer.questions, query_for(&name).questions);
        }
        assert_eq!(server.accepted(), 3);
    }

    /// The pool belongs to the runtime that first used it: after that
    /// runtime is gone, the next query on another runtime replaces the dead
    /// connection transparently.
    #[test]
    fn a_pooled_backend_recovers_when_its_runtime_is_replaced() {
        let server_rt = tokio::runtime::Runtime::new().unwrap();
        let server = server_rt.block_on(CountingServer::start(None));
        let backend = server.backend();

        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        first
            .block_on(backend.resolve(&query_for("one.example.com")))
            .unwrap();
        drop(first);

        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let answer = second
            .block_on(backend.resolve(&query_for("two.example.com")))
            .expect("the dead connection is replaced");
        assert_eq!(answer.questions, query_for("two.example.com").questions);
        assert_eq!(server.accepted(), 2);
    }
}
