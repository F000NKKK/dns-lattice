//! Public async upstream DNS backend trait plus baseline UDP and TCP
//! transport implementations.
//!
//! Stage 0.3 replaces stage 0.2's crate-private, fully synchronous
//! `engine::UpstreamBackend` (ADR-0009) with the public, async
//! [`UpstreamBackend`] trait defined here, per ADR-0011
//! (`DL-A-12`): async via `async_trait` (native `async fn` in traits is not
//! `dyn`-safe and this trait is stored as `Box<dyn UpstreamBackend>`), no
//! per-call timeout parameter (each backend's own config owns its
//! timeout(s)), and one dedicated config struct per transport rather than a
//! shared enum.
//!
//! No EDNS0/OPT support this stage (ADR-0011 point 5): [`UdpBackend`] sends
//! queries with no OPT record and falls back to a TCP query to the same
//! server whenever a UDP response arrives with the `TC` (truncated) bit
//! set, rather than negotiating a larger UDP payload size.
//!
//! # DoT, DoH, and DoQ (feature-gated)
//!
//! Three additional backends land in this module, each behind its own
//! default-off Cargo feature so the baseline UDP/TCP build carries no
//! TLS/HTTP/QUIC dependency weight, per ADR-0012 (`DL-A-13`) and ADR-0013
//! (`DL-A-14`):
//!
//! - `dot` (`#[cfg(feature = "dot")]`): `DotBackend`/`DotBackendConfig`,
//!   DNS-over-TLS (RFC 7858) over `rustls`/`tokio-rustls`.
//! - `doh` (`#[cfg(feature = "doh")]`): `DohBackend`/`DohBackendConfig`,
//!   DNS-over-HTTPS (RFC 8484) over `hyper`/`hyper-rustls`.
//! - `doq` (`#[cfg(feature = "doq")]`): `DoqBackend`/`DoqBackendConfig`,
//!   DNS-over-QUIC (RFC 9250) over `quinn` (TLS 1.3 embedded in QUIC via
//!   `rustls`). Opens a fresh QUIC connection per query in this stage (no
//!   pooling/reuse), reusing the same length-prefixed framing helper as
//!   [`TcpBackend`]/`dot::DotBackend` on one bidirectional stream.
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
//! [`crate::Resolver::resolve`], once a backend of this kind is
//! registered) from inside a `tokio` runtime context.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use dns_lattice_core::{Error, Result};
use dns_lattice_model::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[cfg(feature = "dot")]
mod dot;
#[cfg(feature = "dot")]
pub use dot::{DotBackend, DotBackendConfig};

#[cfg(feature = "doh")]
mod doh;
#[cfg(feature = "doh")]
pub use doh::{DohBackend, DohBackendConfig, DohMethod};

#[cfg(feature = "doq")]
mod doq;
/// `pub(crate)` (not exported from the crate root) so `crate::server`'s DoQ
/// listener (ADR-0016, `DL-A-17` decision 4) can reuse the client-side
/// `QuicStream` `AsyncRead`/`AsyncWrite` adapter unchanged, mirroring how
/// `read_framed`/`write_framed` are already shared between `upstream` and
/// `server`.
#[cfg(feature = "doq")]
pub(crate) use doq::QuicStream;
#[cfg(feature = "doq")]
pub use doq::{DoqBackend, DoqBackendConfig};

/// Maximum size, in bytes, of a UDP response this baseline backend accepts
/// without EDNS0 payload-size negotiation (RFC 1035 §4.2.1's 512-byte
/// standard UDP message size). A larger answer arrives with `TC=1` set and
/// is size-truncated by the responding server itself; [`UdpBackend`] then
/// falls back to a TCP query per ADR-0011 point 5.
///
/// `pub(crate)` (not private) so `crate::server`'s UDP listener can reuse
/// the same boundary when deciding whether to truncate an outbound response
/// and set `TC=1`, per ADR-0015 (`DL-A-16`) point 3 — the baseline server
/// has no larger negotiated payload size to honor either, so it shares this
/// exact constant rather than redefining an equivalent one.
pub(crate) const UDP_MAX_RESPONSE_LEN: usize = 512;

/// A public, async, object-safe upstream DNS backend seam: given a query
/// [`Message`], resolve it against this backend and return the answer.
///
/// Replaces stage 0.2's crate-private `engine::UpstreamBackend` (ADR-0009);
/// see the module-level docs and ADR-0011 (`DL-A-12`) for the full
/// rationale behind this shape. Implementations own their own
/// timeout/retry policy via their transport-specific config — this trait
/// does not accept a timeout argument.
///
/// Custom transports (e.g. DoT/DoH/DoQ, or any future transport) can
/// implement this trait directly and register with
/// [`crate::ResolverBuilder::backend`] alongside [`UdpBackend`]/
/// [`TcpBackend`].
#[async_trait]
pub trait UpstreamBackend: Send + Sync {
    /// Resolves `query` against this backend, returning the answer
    /// [`Message`] or an [`Error`] if the backend itself fails (transport
    /// error, timeout, malformed response).
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
/// (ADR-0011 point 5): falls back to a TCP query to the same server when a
/// response arrives with the `TC` (truncated) bit set.
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

        let mut buf = [0u8; UDP_MAX_RESPONSE_LEN];
        let len = recv_udp(&socket, &mut buf, self.config.timeout).await?;
        let response = Message::decode(&buf[..len])?;

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

async fn recv_udp(socket: &UdpSocket, buf: &mut [u8], budget: Duration) -> Result<usize> {
    timeout(budget, socket.recv(buf))
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

    framed_query(&mut stream, read_timeout, query).await
}

/// Sends `query` over an already-established, ordered byte stream using
/// RFC 1035 §4.2.2's 2-byte big-endian length-prefixed framing, and
/// returns the decoded response. Shared by [`tcp_query`] (plaintext TCP)
/// and, behind the `dot` feature, `dot::DotBackend` (the same framing over
/// an established TLS stream).
///
/// Implemented in terms of [`write_framed`] and [`read_framed`] (ADR-0015,
/// `DL-A-16` point 5) — this one-shot write-then-read shape stays as the
/// client-role helper; `crate::server`'s read-many/respond-many TCP loop
/// calls the two halves directly instead of this function.
pub(crate) async fn framed_query<S>(
    stream: &mut S,
    budget: Duration,
    query: &Message,
) -> Result<Message>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_framed(stream, budget, query).await?;
    read_framed(stream, budget).await
}

/// Writes `message` to `stream` using RFC 1035 §4.2.2's 2-byte big-endian
/// length-prefixed framing (a 2-byte length prefix followed by the encoded
/// message), bounded by `budget`.
///
/// One half of the `framed_query` split (ADR-0015, `DL-A-16` point 5):
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
/// One half of the `framed_query` split (ADR-0015, `DL-A-16` point 5):
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
    use dns_lattice_model::{Class, Header, Name, Opcode, Question, Rcode, RecordType};
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
}
