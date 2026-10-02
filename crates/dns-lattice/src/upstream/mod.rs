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
//! [`UdpBackend`] does not support EDNS0/OPT: it adds no OPT record of its
//! own and falls back to a TCP query to the same server whenever a UDP
//! response arrives with the `TC` (truncated) bit set, rather than
//! negotiating a larger UDP payload size. It sends the query it is given
//! unchanged, so a forwarded client query keeps the client's OPT record and
//! the upstream may answer with more than 512 bytes; the backend receives
//! any UDP DNS payload up to 65535 bytes.
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
//!   `rustls`). Opens a fresh QUIC connection per query in this stage (no
//!   pooling/reuse), reusing the same length-prefixed framing helper as
//!   [`TcpBackend`]/`dot::DotBackend` on one bidirectional stream.
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
//! # Runtime requirement
//!
//! Both [`UdpBackend`] and [`TcpBackend`] perform real socket I/O via
//! `tokio` (`tokio::net`, `tokio::time::timeout`) — callers must invoke
//! [`UpstreamBackend::resolve`] (and therefore
//! [`crate::engine::Resolver::resolve`], once a backend of this kind is
//! registered) from inside a `tokio` runtime context.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout, timeout_at};

#[cfg(feature = "dot")]
mod dot;
#[cfg(feature = "dot")]
pub use dot::{DotBackend, DotBackendConfig};

#[cfg(feature = "doh")]
mod doh;
#[cfg(feature = "doh")]
pub use doh::{Doh3Backend, Doh3BackendConfig, DohBackend, DohBackendConfig, DohMethod};

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

/// Baseline UDP upstream backend (RFC 1035 §4.2.1). No EDNS0/OPT support
/// and falls back to a TCP query to the same server when a
/// response arrives with the `TC` (truncated) bit set.
///
/// A response of any size up to 65535 bytes is accepted, so an answer
/// larger than 512 bytes to a query that carries an OPT record is returned
/// intact rather than cut off.
pub struct UdpBackend {
    config: UdpBackendConfig,
}

impl UdpBackend {
    /// Builds a UDP backend from `config`.
    pub fn new(config: UdpBackendConfig) -> Self {
        Self { config }
    }
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

        let payload = query.encode()?;
        send_udp(&socket, &payload, self.config.timeout).await?;

        // One deadline bounds the whole receive phase: a datagram that does
        // not decode, or is not an answer to this query (wrong id, QR=0, or
        // a different question), is dropped and the backend keeps waiting,
        // so an off-path spoofed reply cannot displace the real one, cannot
        // end the query early, and cannot extend the wait past the
        // configured timeout either.
        let deadline = Instant::now() + self.config.timeout;
        // Heap-allocated: a 64 KiB array would bloat this future's size.
        let mut buf = vec![0u8; UDP_RECV_BUFFER_LEN];
        let response = loop {
            let len = recv_udp(&socket, &mut buf, deadline).await?;
            let Ok(response) = Message::decode(&buf[..len]) else {
                continue;
            };
            if validate_response(query, &response, IdCheck::Match).is_ok() {
                break response;
            }
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
pub struct TcpBackend {
    config: TcpBackendConfig,
}

impl TcpBackend {
    /// Builds a TCP backend from `config`.
    pub fn new(config: TcpBackendConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl UpstreamBackend for TcpBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        tcp_query(
            self.config.server,
            self.config.connect_timeout,
            self.config.read_timeout,
            query,
        )
        .await
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
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(udp_addr).await.unwrap();

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
    }

    #[tokio::test]
    async fn tcp_backend_rejects_mismatching_responses_as_transport_errors() {
        let responders: [fn(&Message) -> Message; 3] = [
            |query| answer_for("example.com", query.header.id.wrapping_add(1)),
            |query| {
                let mut reply = answer_for("example.com", query.header.id);
                reply.header.qr = false;
                reply
            },
            |query| answer_for("example.org", query.header.id),
        ];

        for respond in responders {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let responder = tokio::spawn(serve_one_tcp_response(listener, respond));

            let backend = TcpBackend::new(TcpBackendConfig {
                server: addr,
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
            });

            let err = backend
                .resolve(&query_for("example.com"))
                .await
                .expect_err("a mismatching tcp response is rejected");
            assert!(matches!(err, Error::Transport(_)), "{err:?}");
            responder.await.unwrap();
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
        bad_responder.await.unwrap();
        good_responder.await.unwrap();
    }
}
