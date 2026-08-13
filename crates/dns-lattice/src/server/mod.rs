//! Inbound DNS server listener: binds UDP/TCP (baseline) and, behind the
//! `dot` Cargo feature, DNS-over-TLS (RFC 7858), handing decoded queries to
//! [`crate::engine::Resolver`], fulfilling the embeddable-server-engine goal
//! named in `ARCHITECTURE.md`.
//!
//! The UDP/TCP baseline is extended by the DoT listener
//! (`ServerBuilder::dot_addr`), DoQ
//! listener (`ServerBuilder::doq_addr`), and DoH listener
//! (`ServerBuilder::doh_addr`) extend the same `ServerBuilder`/`Server`
//! types behind the `dot`/`doq`/`doh` Cargo features. DoT reuses the baseline TCP
//! per-connection loop unchanged once the TLS handshake completes; DoQ (RFC
//! 9250) instead accepts one fresh bidirectional QUIC stream per query (RFC
//! 9250 §4.2), reusing the same `read_framed`/`write_framed` framing helpers
//! via the client-side `QuicStream` adapter already defined in
//! [`crate::upstream`]. DoH (RFC 8484) TLS-accepts identically to DoT, then
//! serves ALPN-negotiated HTTP/1.1 or HTTP/2 via `hyper_util`'s
//! protocol-detecting server builder, parsing RFC 8484 GET/POST requests and answering with the resolved
//! [`Message`] as an `application/dns-message` body.
//!
//! # Lifecycle
//!
//! [`ServerBuilder::new`] takes a shared [`Arc<Resolver>`](crate::Resolver)
//! (required so every concurrently spawned per-connection/per-datagram task
//! can hold an independent `'static` handle to it), configure one or more
//! listen addresses, then [`ServerBuilder::bind`] performs the actual
//! socket binds and returns a [`Server`]. [`Server::serve`] runs the
//! UDP/TCP loops until cancelled externally (e.g. process signal) or until
//! the `Server` value itself is dropped; [`Server::serve_until`] runs the
//! same loops but also stops as soon as a caller-supplied future resolves,
//! for graceful, in-process shutdown. Ordinary `Drop` releases the bound
//! sockets — there is no separate explicit shutdown method, matching
//! [`crate::Resolver`]'s existing no-explicit-shutdown precedent extended
//! to also cover the additional socket resources this module owns.
//!
//! # Error handling
//!
//! A query that fails to *decode* at all (malformed inbound bytes) is
//! dropped without a response — RFC 1035 gives the server no reliable
//! `id`/question to echo back in that case. A query that decodes but whose
//! [`Resolver::resolve`](crate::Resolver::resolve) call returns `Err(_)` is
//! answered with a synthesized [`Rcode::ServFail`] response instead, so a
//! client is never left silently unanswered or hanging.
//!
//! DoH cannot simply "drop" a request the way UDP/TCP/DoT/DoQ drop
//! undecodable bytes — HTTP's request/response model requires *some*
//! response. A request whose path does not match the configured endpoint
//! responds HTTP 404; a request using an unsupported method or an
//! unparseable/undecodable GET `dns` parameter or POST body responds HTTP
//! 400, before [`Message::decode`] is even reached. Once a request *does*
//! decode into a [`Message`], it follows the same `ServFail`-and-still-
//! respond policy as every other transport: the HTTP response is always
//! `200 OK` with an `application/dns-message` body, and a `ServFail` rcode
//! inside that body (not an HTTP error status) signals the resolver-side
//! failure, matching RFC 8484's own guidance that DNS `Rcode`s are not
//! carried in the HTTP status line.
//!
//! # Runtime requirement
//!
//! Every public method here performs real socket I/O via `tokio` and must
//! be called from inside a `tokio` runtime context, exactly like
//! [`crate::upstream`]'s backends.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Message, Rcode};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::net::{TcpListener, UdpSocket};

#[cfg(any(feature = "dot", feature = "doh"))]
use tokio_rustls::TlsAcceptor;
#[cfg(any(feature = "dot", feature = "doh"))]
use tokio_rustls::rustls::ServerConfig;

#[cfg(feature = "doh")]
use base64::Engine;
#[cfg(feature = "doh")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "doh")]
use bytes::Buf;
#[cfg(feature = "doh")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "doh")]
use hyper::body::{Bytes, Incoming};
#[cfg(feature = "doh")]
use hyper::service::service_fn;
#[cfg(feature = "doh")]
use hyper::{Request, Response, StatusCode};
#[cfg(feature = "doh")]
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(feature = "doh")]
use hyper_util::server::conn::auto;

use crate::Resolver;
#[cfg(feature = "doq")]
use crate::upstream::QuicStream;
use crate::upstream::{UDP_MAX_RESPONSE_LEN, read_framed, write_framed};

/// Bounds each TCP read/write performed by the server's per-connection
/// loop. Not user-configurable in this stage — a slow/idle client simply
/// has its connection task end (the OS socket is closed on `Drop`) rather
/// than being held open indefinitely; a future stage may expose this as
/// builder configuration if a real deployment needs it tuned.
const TCP_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a [`Server`] from a shared [`Resolver`] and one or more listen
/// addresses.
///
/// Mirrors [`crate::ResolverBuilder`]'s construct-then-build shape, split
/// into a fallible `bind` step since
/// binding a socket is the first point actual I/O/OS errors can occur.
pub struct ServerBuilder {
    resolver: Arc<Resolver>,
    udp_addrs: Vec<SocketAddr>,
    tcp_addrs: Vec<SocketAddr>,
    #[cfg(feature = "dot")]
    dot_addrs: Vec<(SocketAddr, Arc<ServerConfig>)>,
    #[cfg(feature = "doh")]
    doh_addrs: Vec<(SocketAddr, Arc<ServerConfig>, DohListenerConfig)>,
    #[cfg(feature = "doh")]
    doh3_addrs: Vec<(SocketAddr, quinn::ServerConfig, DohListenerConfig)>,
    #[cfg(feature = "doq")]
    doq_addrs: Vec<(SocketAddr, quinn::ServerConfig)>,
}

/// Configuration for a DoH (RFC 8484) listener beyond its TLS config,
/// currently just the URI path the listener answers `GET`/`POST` requests
/// on (RFC 8484 §4.1 uses `/dns-query` as its example/convention path, not
/// a mandated one — this crate does not hardcode it).
///
/// Any request whose path does not match `path` gets an HTTP 404 response,
/// entirely outside `Message`/`Resolver`.
#[cfg(feature = "doh")]
#[derive(Debug, Clone)]
pub struct DohListenerConfig {
    /// The URI path this listener answers DNS-over-HTTPS requests on.
    pub path: String,
}

#[cfg(feature = "doh")]
impl Default for DohListenerConfig {
    /// Defaults to `/dns-query`, matching RFC 8484's own worked examples
    /// and the convention most public DoH resolvers use.
    fn default() -> Self {
        DohListenerConfig {
            path: "/dns-query".to_string(),
        }
    }
}

impl ServerBuilder {
    /// Starts building a server that answers queries via `resolver`.
    ///
    /// Takes `Arc<Resolver>` (not `Resolver` by value or `&Resolver`)
    /// because the resolver must outlive, and be shared across, every
    /// concurrently spawned per-connection/per-datagram `tokio::task`
    /// so each task can hold an independent handle.
    pub fn new(resolver: Arc<Resolver>) -> Self {
        ServerBuilder {
            resolver,
            udp_addrs: Vec::new(),
            tcp_addrs: Vec::new(),
            #[cfg(feature = "dot")]
            dot_addrs: Vec::new(),
            #[cfg(feature = "doh")]
            doh_addrs: Vec::new(),
            #[cfg(feature = "doh")]
            doh3_addrs: Vec::new(),
            #[cfg(feature = "doq")]
            doq_addrs: Vec::new(),
        }
    }

    /// Adds a UDP address to bind. May be called more than once to bind
    /// multiple UDP addresses.
    pub fn udp_addr(mut self, addr: SocketAddr) -> Self {
        self.udp_addrs.push(addr);
        self
    }

    /// Adds a TCP address to bind. May be called more than once to bind
    /// multiple TCP addresses.
    pub fn tcp_addr(mut self, addr: SocketAddr) -> Self {
        self.tcp_addrs.push(addr);
        self
    }

    /// Adds a DNS-over-TLS (RFC 7858) address to bind, with `tls_config`
    /// used to accept the TLS session on every connection to that address
    /// May be called more than once to
    /// bind multiple DoT addresses, each with its own `tls_config`.
    ///
    /// This crate does not source certificate material itself — the caller supplies a
    /// fully configured `Arc<rustls::ServerConfig>`, exactly like
    /// [`crate::upstream::DotBackendConfig`]'s existing
    /// `Arc<ClientConfig>` ownership pattern on the client side.
    #[cfg(feature = "dot")]
    pub fn dot_addr(mut self, addr: SocketAddr, tls_config: Arc<ServerConfig>) -> Self {
        self.dot_addrs.push((addr, tls_config));
        self
    }

    /// Adds a DNS-over-HTTPS (RFC 8484) address to bind, with `tls_config`
    /// used to accept the TLS session on every connection to that address
    /// and `config` selecting the URI path answered. May be called more than once to bind multiple DoH
    /// addresses, each with its own `tls_config`/`config`.
    ///
    /// This crate does not source certificate material itself — the caller
    /// supplies a
    /// fully configured `Arc<rustls::ServerConfig>`, exactly like
    /// [`ServerBuilder::dot_addr`]. A deployment that serves both DoH HTTP
    /// versions must configure its ALPN list with `h2` and `http/1.1`; the
    /// listener serves whichever protocol TLS negotiates.
    #[cfg(feature = "doh")]
    pub fn doh_addr(
        mut self,
        addr: SocketAddr,
        tls_config: Arc<ServerConfig>,
        config: DohListenerConfig,
    ) -> Self {
        self.doh_addrs.push((addr, tls_config, config));
        self
    }

    /// Adds a DNS-over-HTTPS HTTP/3 (RFC 9114) UDP/QUIC address. This is
    /// additive to [`ServerBuilder::doh_addr`], which remains the TCP path
    /// for HTTP/1.1 and HTTP/2 (including TLS 1.2 legacy clients).
    ///
    /// `server_config` must be a QUIC `quinn::ServerConfig` whose embedded
    /// TLS configuration advertises ALPN `h3`. QUIC mandates TLS 1.3, so a
    /// host serving all DoH generations binds this UDP address as well as a
    /// TCP [`ServerBuilder::doh_addr`] address.
    #[cfg(feature = "doh")]
    pub fn doh3_addr(
        mut self,
        addr: SocketAddr,
        server_config: quinn::ServerConfig,
        config: DohListenerConfig,
    ) -> Self {
        self.doh3_addrs.push((addr, server_config, config));
        self
    }

    /// Adds a DNS-over-QUIC (RFC 9250) address to bind, with `server_config`
    /// used to establish every QUIC connection's embedded TLS 1.3 session on
    /// that address. May be called more
    /// than once to bind multiple DoQ addresses, each with its own
    /// `server_config`.
    ///
    /// This crate does not source certificate material itself, and it does not
    /// special-case ALPN negotiation inside the listener — `server_config`'s
    /// embedded `rustls` crypto config MUST already advertise the `doq` ALPN
    /// protocol identifier (RFC 9250 §4.1.1); this is the caller's
    /// responsibility, mirroring [`crate::upstream::DoqBackendConfig`]'s
    /// existing client-side `tls_config`/ALPN ownership pattern.
    #[cfg(feature = "doq")]
    pub fn doq_addr(mut self, addr: SocketAddr, server_config: quinn::ServerConfig) -> Self {
        self.doq_addrs.push((addr, server_config));
        self
    }

    /// Binds every configured UDP/TCP address and returns the bound
    /// [`Server`], ready to [`Server::serve`].
    ///
    /// Binding a privileged port (e.g. `0.0.0.0:53` on Unix) is the
    /// composing application's responsibility, not this crate's — a permission-denied OS error surfaces here as an
    /// ordinary [`Error::Transport`], exactly like `upstream`'s existing
    /// bind/connect error mapping, with no special-cased privilege check.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if any configured address fails to
    /// bind (already in use, permission denied, invalid address, ...).
    pub async fn bind(self) -> Result<Server> {
        let mut udp_sockets = Vec::with_capacity(self.udp_addrs.len());
        for addr in self.udp_addrs {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|err| Error::Transport(err.to_string()))?;
            udp_sockets.push(socket);
        }

        let mut tcp_listeners = Vec::with_capacity(self.tcp_addrs.len());
        for addr in self.tcp_addrs {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| Error::Transport(err.to_string()))?;
            tcp_listeners.push(listener);
        }

        #[cfg(feature = "dot")]
        let mut dot_listeners = Vec::with_capacity(self.dot_addrs.len());
        #[cfg(feature = "dot")]
        for (addr, tls_config) in self.dot_addrs {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| Error::Transport(err.to_string()))?;
            dot_listeners.push((listener, TlsAcceptor::from(tls_config)));
        }

        #[cfg(feature = "doh")]
        let mut doh_listeners = Vec::with_capacity(self.doh_addrs.len());
        #[cfg(feature = "doh")]
        for (addr, tls_config, config) in self.doh_addrs {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|err| Error::Transport(err.to_string()))?;
            doh_listeners.push((listener, TlsAcceptor::from(tls_config), config));
        }

        #[cfg(feature = "doh")]
        let mut doh3_endpoints = Vec::with_capacity(self.doh3_addrs.len());
        #[cfg(feature = "doh")]
        for (addr, server_config, config) in self.doh3_addrs {
            let endpoint = quinn::Endpoint::server(server_config, addr)
                .map_err(|err| Error::Transport(err.to_string()))?;
            doh3_endpoints.push((endpoint, config));
        }

        #[cfg(feature = "doq")]
        let mut doq_endpoints = Vec::with_capacity(self.doq_addrs.len());
        #[cfg(feature = "doq")]
        for (addr, server_config) in self.doq_addrs {
            let endpoint = quinn::Endpoint::server(server_config, addr)
                .map_err(|err| Error::Transport(err.to_string()))?;
            doq_endpoints.push(endpoint);
        }

        Ok(Server {
            resolver: self.resolver,
            udp_sockets,
            tcp_listeners,
            #[cfg(feature = "dot")]
            dot_listeners,
            #[cfg(feature = "doh")]
            doh_listeners,
            #[cfg(feature = "doh")]
            doh3_endpoints,
            #[cfg(feature = "doq")]
            doq_endpoints,
        })
    }
}

/// A bound DNS server: one or more UDP sockets and TCP listeners, each
/// backed by the same shared [`Resolver`]. Construct via
/// [`ServerBuilder::new`] and [`ServerBuilder::bind`].
pub struct Server {
    resolver: Arc<Resolver>,
    udp_sockets: Vec<UdpSocket>,
    tcp_listeners: Vec<TcpListener>,
    #[cfg(feature = "dot")]
    dot_listeners: Vec<(TcpListener, TlsAcceptor)>,
    #[cfg(feature = "doh")]
    doh_listeners: Vec<(TcpListener, TlsAcceptor, DohListenerConfig)>,
    #[cfg(feature = "doh")]
    doh3_endpoints: Vec<(quinn::Endpoint, DohListenerConfig)>,
    #[cfg(feature = "doq")]
    doq_endpoints: Vec<quinn::Endpoint>,
}

impl Server {
    /// Runs every configured UDP recv loop and TCP accept loop
    /// concurrently, forever (until the process exits or every bound
    /// socket errors out unrecoverably — a `recv`/`accept` failure on any
    /// one bound socket).
    ///
    /// Most callers that need graceful, in-process shutdown should use
    /// [`Server::serve_until`] instead; this method has no built-in way to
    /// stop early short of dropping/aborting its containing task.
    pub async fn serve(self) -> Result<()> {
        self.serve_until(std::future::pending()).await
    }

    /// Runs every configured UDP recv loop and TCP accept loop
    /// concurrently until `shutdown` resolves, then returns `Ok(())`
    /// without waiting for in-flight per-connection/per-datagram tasks to
    /// finish (they are independently spawned and will complete or be
    /// dropped on their own as the runtime shuts down) — matching
    /// `Resolver`'s existing no-explicit-shutdown precedent: this method's
    /// return, followed by `self`'s `Drop`, is what releases the bound
    /// sockets, not a distinct drain/join step.
    ///
    /// `shutdown` is typically a `tokio::sync::oneshot::Receiver`, a
    /// `tokio::sync::watch::Receiver` change notification, or
    /// `tokio::signal::ctrl_c()` mapped to `()` — anything that resolves
    /// once when the caller wants the listener loops to stop.
    pub async fn serve_until(self, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
        let Server {
            resolver,
            udp_sockets,
            tcp_listeners,
            #[cfg(feature = "dot")]
            dot_listeners,
            #[cfg(feature = "doh")]
            doh_listeners,
            #[cfg(feature = "doh")]
            doh3_endpoints,
            #[cfg(feature = "doq")]
            doq_endpoints,
        } = self;

        let udp_sockets: Vec<Arc<UdpSocket>> = udp_sockets.into_iter().map(Arc::new).collect();

        let mut loops = tokio::task::JoinSet::new();
        for socket in udp_sockets {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_udp(socket, resolver).await });
        }
        for listener in tcp_listeners {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_tcp(listener, resolver).await });
        }
        #[cfg(feature = "dot")]
        for (listener, acceptor) in dot_listeners {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_dot(listener, acceptor, resolver).await });
        }
        #[cfg(feature = "doh")]
        for (listener, acceptor, config) in doh_listeners {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_doh(listener, acceptor, config, resolver).await });
        }
        #[cfg(feature = "doh")]
        for (endpoint, config) in doh3_endpoints {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_doh3(endpoint, config, resolver).await });
        }
        #[cfg(feature = "doq")]
        for endpoint in doq_endpoints {
            let resolver = resolver.clone();
            loops.spawn(async move { serve_doq(endpoint, resolver).await });
        }

        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => {
                loops.abort_all();
                Ok(())
            }
            // A listener loop only returns on an unrecoverable per-socket
            // error (see `serve_udp`/`serve_tcp`'s docs) — surface the
            // first one and stop every other loop rather than leaking
            // tasks silently.
            Some(result) = loops.join_next() => {
                loops.abort_all();
                match result {
                    Ok(Err(err)) => Err(err),
                    Ok(Ok(())) => Ok(()),
                    Err(join_err) => Err(Error::Transport(join_err.to_string())),
                }
            }
        }
    }
}

/// Runs `socket`'s UDP receive loop forever: one `tokio::task` is spawned
/// per received datagram so one slow
/// resolution never stalls receiving the next datagram. Only returns (with
/// `Err`) if `recv_from` itself fails, which is treated as unrecoverable
/// for this socket.
async fn serve_udp(socket: Arc<UdpSocket>, resolver: Arc<Resolver>) -> Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, from) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|err| Error::Transport(err.to_string()))?;
        let payload = buf[..len].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            handle_udp_datagram(&socket, &resolver, &payload, from).await;
        });
    }
}

/// Decodes, resolves, and answers one inbound UDP datagram. Undecodable
/// bytes are dropped (logged nowhere in this stage — no logging facade
/// exists yet; see module docs) rather than answered, since there is no
/// reliable `id`/question to echo back for a message that failed to parse.
async fn handle_udp_datagram(
    socket: &UdpSocket,
    resolver: &Resolver,
    payload: &[u8],
    from: SocketAddr,
) {
    let Ok(query) = Message::decode(payload) else {
        return;
    };

    let mut response = match resolver.resolve(&query).await {
        Ok(answer) => answer,
        Err(_) => servfail_response(&query),
    };

    let Ok(mut encoded) = response.encode() else {
        // Encoding a synthesized/passthrough response should not normally
        // fail (it round-trips a message the resolver itself produced or a
        // trivial ServFail synthesis), but if it ever does there is
        // nothing more this datagram handler can do — drop rather than
        // panic.
        return;
    };

    if encoded.len() > UDP_MAX_RESPONSE_LEN {
        response.answers.clear();
        response.authorities.clear();
        response.additionals.clear();
        response.header.truncated = true;
        encoded = match response.encode() {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
    }

    let _ = socket.send_to(&encoded, from).await;
}

/// Runs `listener`'s TCP accept loop forever: one `tokio::task` per
/// accepted connection, each looping over
/// as many length-prefixed queries as the client sends on that connection.
/// Only returns (with `Err`) if `accept` itself fails, which is treated as
/// unrecoverable for this listener.
async fn serve_tcp(listener: TcpListener, resolver: Arc<Resolver>) -> Result<()> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|err| Error::Transport(err.to_string()))?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            handle_tcp_connection(stream, &resolver).await;
        });
    }
}

/// Runs `listener`'s DoT (RFC 7858) accept loop forever, mirroring
/// [`serve_tcp`]: one `tokio::task` per accepted connection. The TLS accept itself happens *inside* the
/// spawned per-connection task, not in this accept loop, so a single
/// slow/hostile handshake cannot stall accepting the next connection — same
/// non-blocking-accept-loop principle as `serve_tcp`. A handshake failure
/// ends that connection's task without a response (no reliable peer
/// identity/session to answer on a failed handshake, matching the
/// undecodable-datagram policy).
#[cfg(feature = "dot")]
async fn serve_dot(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    resolver: Arc<Resolver>,
) -> Result<()> {
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|err| Error::Transport(err.to_string()))?;
        let acceptor = acceptor.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            handle_tcp_connection(tls_stream, &resolver).await;
        });
    }
}

/// Runs `listener`'s DoH (RFC 8484) accept loop forever, mirroring
/// [`serve_dot`]: TLS-accept happens inside the spawned per-connection task,
/// not this accept loop (same non-blocking-accept-loop principle). Once the
/// TLS handshake completes, the connection is served as its ALPN-negotiated
/// HTTP/1.1 or HTTP/2 protocol via `hyper_util`'s protocol-detecting
/// [`auto::Builder`] (the `server-auto` feature) with a [`service_fn`] closure that dispatches to
/// [`handle_doh_request`] for every request on the connection. A handshake
/// failure ends that connection's task without a response, matching DoT.
#[cfg(feature = "doh")]
async fn serve_doh(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: DohListenerConfig,
    resolver: Arc<Resolver>,
) -> Result<()> {
    let config = Arc::new(config);
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .map_err(|err| Error::Transport(err.to_string()))?;
        let acceptor = acceptor.clone();
        let resolver = resolver.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let Ok(tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let resolver = resolver.clone();
                let config = config.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle_doh_request(req, config, resolver).await,
                    )
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        });
    }
}

/// Answers one RFC 8484 DoH request: routes on `config.path`, extracts the
/// wire-format query bytes per the request's method (GET's base64url `dns`
/// query parameter or POST's `application/dns-message` body), decodes,
/// resolves, and re-encodes the answer, following the same
/// `Result`-to-response pattern as [`handle_tcp_connection`]/
/// [`handle_doq_stream`].
///
/// See the module-level "Error handling" docs for exactly which failures map
/// to which HTTP status: a path mismatch is HTTP 404; an unsupported method
/// or a request whose bytes cannot even be extracted/decoded into a
/// [`Message`] is HTTP 400; everything that decodes successfully is HTTP 200
/// with an `application/dns-message` body, `ServFail` included.
#[cfg(feature = "doh")]
async fn handle_doh_request(
    req: Request<Incoming>,
    config: Arc<DohListenerConfig>,
    resolver: Arc<Resolver>,
) -> Response<Full<Bytes>> {
    if req.uri().path() != config.path {
        return http_status_response(StatusCode::NOT_FOUND);
    }

    let query_bytes = match extract_query_bytes(req).await {
        Some(bytes) => bytes,
        None => return http_status_response(StatusCode::BAD_REQUEST),
    };

    let Ok(query) = Message::decode(&query_bytes) else {
        return http_status_response(StatusCode::BAD_REQUEST);
    };

    let response = match resolver.resolve(&query).await {
        Ok(answer) => answer,
        Err(_) => servfail_response(&query),
    };

    let Ok(encoded) = response.encode() else {
        return http_status_response(StatusCode::INTERNAL_SERVER_ERROR);
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(encoded)))
        .unwrap_or_else(|_| http_status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Extracts the raw wire-format DNS query bytes from a DoH request per RFC
/// 8484 §4.1: GET's base64url-encoded `dns` query parameter, or POST's raw
/// `application/dns-message` body. Returns `None` for any other method, a
/// GET with no/unparseable `dns` parameter, or a body read failure — the
/// caller maps `None` to HTTP 400.
#[cfg(feature = "doh")]
async fn extract_query_bytes(req: Request<Incoming>) -> Option<Vec<u8>> {
    match *req.method() {
        hyper::Method::GET => {
            let query = req.uri().query()?;
            let encoded = query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "dns").then_some(value)
            })?;
            URL_SAFE_NO_PAD.decode(encoded).ok()
        }
        hyper::Method::POST => {
            let body = req.into_body().collect().await.ok()?;
            Some(body.to_bytes().to_vec())
        }
        _ => None,
    }
}

/// Builds an empty-body HTTP response carrying only `status`, used for the
/// HTTP-layer routing/parsing rejections [`handle_doh_request`] issues
/// before a [`Message`] is ever decoded.
#[cfg(feature = "doh")]
fn http_status_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("a bare status response always builds")
}

/// Runs the UDP/QUIC HTTP/3 DoH accept loop. This intentionally shares the
/// HTTP request-to-DNS response policy with TCP DoH while retaining QUIC's
/// TLS-1.3-only and `h3` ALPN boundary.
#[cfg(feature = "doh")]
async fn serve_doh3(
    endpoint: quinn::Endpoint,
    config: DohListenerConfig,
    resolver: Arc<Resolver>,
) -> Result<()> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let config = config.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            let Some(data) = connection
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            else {
                return;
            };
            if data.protocol.as_deref() != Some(b"h3") {
                return;
            }
            let Ok(mut h3_connection) =
                h3::server::Connection::new(h3_quinn::Connection::new(connection)).await
            else {
                return;
            };
            while let Ok(Some(request)) = h3_connection.accept().await {
                let config = config.clone();
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    let Ok((request, mut stream)) = request.resolve_request().await else {
                        return;
                    };
                    let mut body = Vec::new();
                    while let Ok(Some(chunk)) = stream.recv_data().await {
                        body.extend_from_slice(chunk.chunk());
                    }
                    let query_bytes = extract_doh3_query_bytes(&request, body);
                    let (status, payload) =
                        match query_bytes.and_then(|bytes| Message::decode(&bytes).ok()) {
                            Some(query) if request.uri().path() == config.path => {
                                let answer = resolver
                                    .resolve(&query)
                                    .await
                                    .unwrap_or_else(|_| servfail_response(&query));
                                match answer.encode() {
                                    Ok(bytes) => (StatusCode::OK, bytes),
                                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Vec::new()),
                                }
                            }
                            Some(_) => (StatusCode::NOT_FOUND, Vec::new()),
                            None => (StatusCode::BAD_REQUEST, Vec::new()),
                        };
                    let response = Response::builder()
                        .status(status)
                        .header("content-type", "application/dns-message")
                        .body(())
                        .unwrap();
                    if stream.send_response(response).await.is_ok() {
                        if !payload.is_empty() {
                            let _ = stream.send_data(Bytes::from(payload)).await;
                        }
                        let _ = stream.finish().await;
                    }
                });
            }
        });
    }
}

#[cfg(feature = "doh")]
fn extract_doh3_query_bytes(request: &http::Request<()>, body: Vec<u8>) -> Option<Vec<u8>> {
    match *request.method() {
        hyper::Method::GET => {
            let encoded = request.uri().query()?.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "dns").then_some(value)
            })?;
            URL_SAFE_NO_PAD.decode(encoded).ok()
        }
        hyper::Method::POST => Some(body),
        _ => None,
    }
}

/// Runs `endpoint`'s DoQ (RFC 9250) accept loop forever: one `tokio::task`
/// per accepted QUIC connection, mirroring
/// the non-blocking-accept-loop principle `serve_tcp`/`serve_dot` already
/// establish — a single slow/hostile handshake cannot stall accepting the
/// next connection. Once a connection's handshake completes, the task loops
/// on `Connection::accept_bi`, spawning one further `tokio::task` per
/// accepted bidirectional stream, since RFC 9250 §4.2 puts each query on its
/// own fresh stream rather than reusing one stream for many queries (unlike
/// DoT/TCP). Returns `Ok(())` once `endpoint.accept()` yields `None` (the
/// endpoint was closed), or `Err` if the endpoint itself becomes
/// unrecoverable.
#[cfg(feature = "doq")]
async fn serve_doq(endpoint: quinn::Endpoint, resolver: Arc<Resolver>) -> Result<()> {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                // Handshake failure: no reliable peer session to answer on,
                // matching the DoT/TLS handshake-failure policy.
                return;
            };
            loop {
                let (send, recv) = match connection.accept_bi().await {
                    Ok(pair) => pair,
                    // Connection closed or errored: end this connection's
                    // task, matching `handle_tcp_connection`'s
                    // end-of-connection policy.
                    Err(_) => return,
                };
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    handle_doq_stream(send, recv, &resolver).await;
                });
            }
        });
    }
}

/// Serves one accepted DoQ bidirectional stream: reads exactly one
/// length-prefixed query, resolves it, and writes exactly one
/// length-prefixed response (RFC 9250 §4.2's one-stream-per-query framing,
/// distinct from DoT/TCP's one-connection-many-queries loop in
/// [`handle_tcp_connection`]). Wraps `send`/`recv` in [`QuicStream`]
/// (`crate::upstream`'s existing client-side adapter) so the same [`read_framed`]/
/// [`write_framed`] helpers apply. A decode/resolve/write failure ends the
/// stream without a response, same undecodable-message policy as UDP/TCP/
/// DoT.
#[cfg(feature = "doq")]
async fn handle_doq_stream(send: quinn::SendStream, recv: quinn::RecvStream, resolver: &Resolver) {
    let mut stream = QuicStream { send, recv };

    let query = match read_framed(&mut stream, TCP_IO_TIMEOUT).await {
        Ok(query) => query,
        Err(_) => return,
    };

    let response = match resolver.resolve(&query).await {
        Ok(answer) => answer,
        Err(_) => servfail_response(&query),
    };

    if write_framed(&mut stream, TCP_IO_TIMEOUT, &response)
        .await
        .is_err()
    {
        return;
    }

    // Per RFC 9250 §4.2, the server SHOULD close the send side of the
    // stream gracefully after sending the response, mirroring
    // `DoqBackend::resolve`'s own client-side `finish()` call.
    let _ = stream.send.finish();
}

/// Serves one accepted TCP (or TLS-wrapped TCP, for DoT) connection:
/// repeatedly reads a length-prefixed query and writes back a
/// length-prefixed response until the connection closes or a read/write
/// error occurs, so a single connection can carry multiple back-to-back
/// queries (RFC 1035 §4.2.2). Generic over `S: AsyncRead + AsyncWrite +
/// Unpin` so the baseline TCP listener and the DoT listener
/// share this exact loop body unchanged —
/// a `tokio_rustls::server::TlsStream<TcpStream>` implements the same
/// bound as a plain `TcpStream`.
async fn handle_tcp_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    resolver: &Resolver,
) {
    loop {
        let query = match read_framed(&mut stream, TCP_IO_TIMEOUT).await {
            Ok(query) => query,
            // Either the connection closed/errored, or a frame failed to
            // decode; both end this connection's loop. A decode failure
            // has no reliable id/question to answer with any more than the
            // UDP case does, so it is treated the same way here.
            Err(_) => return,
        };

        let response = match resolver.resolve(&query).await {
            Ok(answer) => answer,
            Err(_) => servfail_response(&query),
        };

        if write_framed(&mut stream, TCP_IO_TIMEOUT, &response)
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Synthesizes an [`Rcode::ServFail`] response echoing `query`'s `id` and
/// question section, used whenever
/// [`Resolver::resolve`](crate::Resolver::resolve) returns `Err(_)` for a
/// query that *did* decode successfully.
fn servfail_response(query: &Message) -> Message {
    let mut header = query.header;
    header.qr = true;
    header.rcode = Rcode::ServFail;
    Message {
        header,
        questions: query.questions.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dns_lattice_model::{
        Class, DomainPattern, Header, Name, Opcode, Question, RData, RecordType, ResourceRecord,
        SplitDnsPolicy, UpstreamGroupId,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    use crate::fakeip::{FakeIpPolicy, FakeIpPool};
    use crate::upstream::UpstreamBackend;

    fn query_for(name: &str, id: u16) -> Message {
        Message {
            header: Header {
                id,
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

    fn answer_with_a(name: &str, id: u16, addr: std::net::Ipv4Addr) -> Message {
        let mut msg = query_for(name, id);
        msg.header.qr = true;
        msg.answers.push(ResourceRecord {
            name: Name::from_ascii(name).unwrap(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 300,
            rdata: RData::A(addr),
        });
        msg
    }

    /// A fixed-answer fake [`UpstreamBackend`] that echoes the inbound
    /// query's `id` onto its fixed answer (matching real resolver
    /// behavior), so round-trip tests can assert on the id they sent.
    struct FixedBackend(Message);

    #[async_trait]
    impl UpstreamBackend for FixedBackend {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            let mut answer = self.0.clone();
            answer.header.id = query.header.id;
            Ok(answer)
        }
    }

    /// A fake [`UpstreamBackend`] that always fails, used to exercise
    /// ServFail synthesis.
    struct FailingBackend;

    #[async_trait]
    impl UpstreamBackend for FailingBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            Err(Error::NoRoute)
        }
    }

    /// A fake [`UpstreamBackend`] that returns a large answer (many `A`
    /// records) so the encoded response exceeds [`UDP_MAX_RESPONSE_LEN`],
    /// used to exercise UDP truncation.
    struct OversizedBackend;

    #[async_trait]
    impl UpstreamBackend for OversizedBackend {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            let mut msg = query.clone();
            msg.header.qr = true;
            for i in 0..100u8 {
                msg.answers.push(ResourceRecord {
                    name: query.questions[0].name.clone(),
                    rtype: RecordType::A,
                    class: Class::In,
                    ttl: 300,
                    rdata: RData::A(std::net::Ipv4Addr::new(203, 0, 113, i)),
                });
            }
            Ok(msg)
        }
    }

    fn resolver_with(backend: impl UpstreamBackend + 'static) -> Arc<Resolver> {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        Arc::new(
            Resolver::builder(policy)
                .backend(UpstreamGroupId::new("g"), backend)
                .build(),
        )
    }

    fn resolver_with_fake_ip(backend: impl UpstreamBackend + 'static) -> Arc<Resolver> {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let pool = Arc::new(
            FakeIpPool::builder()
                .ipv4_range("198.18.0.1".parse().unwrap(), "198.18.0.2".parse().unwrap())
                .ipv6_range(
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::2".parse().unwrap(),
                )
                .ttl(Duration::from_secs(60))
                .build()
                .unwrap(),
        );
        let fake_ip_policy = FakeIpPolicy::builder()
            .rule(DomainPattern::suffix(
                Name::from_ascii("fake.test").unwrap(),
            ))
            .build();
        Arc::new(
            Resolver::builder(policy)
                .backend(UpstreamGroupId::new("g"), backend)
                .fake_ip(pool, fake_ip_policy)
                .build(),
        )
    }

    fn query_for_type(name: &str, qtype: RecordType, id: u16) -> Message {
        let mut query = query_for(name, id);
        query.questions[0].qtype = qtype;
        query
    }

    fn ipv4_reverse_name(address: std::net::Ipv4Addr) -> String {
        let octets = address.octets();
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    fn ipv6_reverse_name(address: std::net::Ipv6Addr) -> String {
        address
            .octets()
            .iter()
            .rev()
            .flat_map(|byte| [format!("{:x}", byte & 0x0f), format!("{:x}", byte >> 4)])
            .collect::<Vec<_>>()
            .join(".")
            + ".ip6.arpa"
    }

    async fn tcp_round_trip(stream: &mut TcpStream, query: &Message) -> Message {
        let payload = query.encode().unwrap();
        let len: u16 = payload.len().try_into().unwrap();
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        stream.write_all(&payload).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let response_len = u16::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await.unwrap();
        Message::decode(&response_buf).unwrap()
    }

    async fn udp_round_trip(client: &UdpSocket, addr: SocketAddr, query: &Message) -> Message {
        client
            .send_to(&query.encode().unwrap(), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response arrives in time")
            .unwrap();
        Message::decode(&buf[..len]).unwrap()
    }

    #[tokio::test]
    async fn udp_round_trip_success() {
        let resolver = resolver_with(FixedBackend(answer_with_a(
            "example.com",
            0,
            std::net::Ipv4Addr::new(203, 0, 113, 1),
        )));
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.udp_sockets[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query_for("example.com", 42);
        client
            .send_to(&query.encode().unwrap(), addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response arrives in time")
            .unwrap();
        let response = Message::decode(&buf[..len]).unwrap();
        assert!(response.header.qr);
        assert_eq!(response.header.id, 42);
        assert_eq!(response.header.rcode, Rcode::NoError);
        assert_eq!(response.answers.len(), 1);

        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_fake_ip_a_and_ptr_are_synthesized_while_policy_miss_uses_upstream() {
        let resolver = resolver_with_fake_ip(FixedBackend(answer_with_a(
            "upstream.test",
            0,
            "203.0.113.80".parse().unwrap(),
        )));
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp");
        let addr = server.udp_sockets[0].local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let synthetic = udp_round_trip(&client, addr, &query_for("www.fake.test", 61)).await;
        assert_eq!(synthetic.header.id, 61);
        assert_eq!(synthetic.answers.len(), 1);
        assert_eq!(
            synthetic.answers[0].rdata,
            RData::A("198.18.0.1".parse().unwrap())
        );

        let reverse = ipv4_reverse_name("198.18.0.1".parse().unwrap());
        let ptr = udp_round_trip(
            &client,
            addr,
            &query_for_type(&reverse, RecordType::Ptr, 62),
        )
        .await;
        assert_eq!(ptr.header.id, 62);
        assert_eq!(ptr.header.rcode, Rcode::NoError);
        assert_eq!(
            ptr.answers[0].rdata,
            RData::Ptr(Name::from_ascii("www.fake.test").unwrap())
        );

        let fallback = udp_round_trip(&client, addr, &query_for("upstream.test", 63)).await;
        assert_eq!(fallback.header.id, 63);
        assert_eq!(
            fallback.answers[0].rdata,
            RData::A("203.0.113.80".parse().unwrap())
        );

        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tcp_round_trip_multiple_queries_over_one_connection() {
        let resolver = resolver_with(FixedBackend(answer_with_a(
            "example.com",
            0,
            std::net::Ipv4Addr::new(203, 0, 113, 2),
        )));
        let server = ServerBuilder::new(resolver)
            .tcp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds tcp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.tcp_listeners[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .expect("connects in time")
            .unwrap();

        for id in [1u16, 2u16, 3u16] {
            // Distinct names per query so the resolver's answer cache
            // (unrelated to this test) does not serve a stale cached `id`
            // from an earlier iteration back for a later one.
            let query = query_for(&format!("q{id}.example.com"), id);
            let payload = query.encode().unwrap();
            let len: u16 = payload.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(&payload);
            stream.write_all(&framed).await.unwrap();

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response_buf = vec![0u8; response_len];
            stream.read_exact(&mut response_buf).await.unwrap();
            let response = Message::decode(&response_buf).unwrap();
            assert!(response.header.qr);
            assert_eq!(response.header.id, id);
        }

        drop(stream);
        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tcp_fake_ip_aaaa_and_ptr_are_synthesized_while_policy_miss_uses_upstream() {
        let resolver = resolver_with_fake_ip(FixedBackend(answer_with_a(
            "upstream.test",
            0,
            "203.0.113.81".parse().unwrap(),
        )));
        let server = ServerBuilder::new(resolver)
            .tcp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds tcp");
        let addr = server.tcp_listeners[0].local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let synthetic = tcp_round_trip(
            &mut stream,
            &query_for_type("www.fake.test", RecordType::Aaaa, 71),
        )
        .await;
        assert_eq!(synthetic.header.id, 71);
        assert_eq!(synthetic.answers.len(), 1);
        assert_eq!(
            synthetic.answers[0].rdata,
            RData::Aaaa("2001:db8::1".parse().unwrap())
        );

        let reverse = ipv6_reverse_name("2001:db8::1".parse().unwrap());
        let ptr = tcp_round_trip(&mut stream, &query_for_type(&reverse, RecordType::Ptr, 72)).await;
        assert_eq!(ptr.header.id, 72);
        assert_eq!(ptr.header.rcode, Rcode::NoError);
        assert_eq!(
            ptr.answers[0].rdata,
            RData::Ptr(Name::from_ascii("www.fake.test").unwrap())
        );

        let fallback = tcp_round_trip(&mut stream, &query_for("upstream.test", 73)).await;
        assert_eq!(fallback.header.id, 73);
        assert_eq!(
            fallback.answers[0].rdata,
            RData::A("203.0.113.81".parse().unwrap())
        );

        drop(stream);
        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_response_truncated_when_oversized() {
        let resolver = resolver_with(OversizedBackend);
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.udp_sockets[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query_for("example.com", 7);
        client
            .send_to(&query.encode().unwrap(), addr)
            .await
            .unwrap();

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response arrives in time")
            .unwrap();
        assert!(
            len <= UDP_MAX_RESPONSE_LEN,
            "truncated response fits within the 512-byte boundary"
        );
        let response = Message::decode(&buf[..len]).unwrap();
        assert!(response.header.truncated, "TC bit is set");
        assert!(response.answers.is_empty());

        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_servfail_synthesized_on_resolver_error() {
        let resolver = resolver_with(FailingBackend);
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.udp_sockets[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = query_for("nope.example.com", 99);
        client
            .send_to(&query.encode().unwrap(), addr)
            .await
            .unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("response arrives in time")
            .unwrap();
        let response = Message::decode(&buf[..len]).unwrap();
        assert!(response.header.qr);
        assert_eq!(response.header.id, 99);
        assert_eq!(response.header.rcode, Rcode::ServFail);
        assert_eq!(response.questions, query.questions);

        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tcp_servfail_synthesized_on_resolver_error() {
        let resolver = resolver_with(FailingBackend);
        let server = ServerBuilder::new(resolver)
            .tcp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds tcp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.tcp_listeners[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
            .await
            .expect("connects in time")
            .unwrap();

        let query = query_for("nope.example.com", 5);
        let payload = query.encode().unwrap();
        let len: u16 = payload.len().try_into().unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&payload);
        stream.write_all(&framed).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let response_len = u16::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];
        stream.read_exact(&mut response_buf).await.unwrap();
        let response = Message::decode(&response_buf).unwrap();
        assert_eq!(response.header.rcode, Rcode::ServFail);
        assert_eq!(response.header.id, 5);

        drop(stream);
        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_udp_datagram_is_dropped_not_answered() {
        let resolver = resolver_with(FixedBackend(answer_with_a(
            "example.com",
            0,
            std::net::Ipv4Addr::new(203, 0, 113, 3),
        )));
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let addr = server.udp_sockets[0].local_addr().unwrap();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Fewer than 12 bytes: not a decodable DNS header.
        client.send_to(&[0u8; 3], addr).await.unwrap();

        // No response should arrive; assert the recv times out instead.
        let mut buf = [0u8; 512];
        let result =
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
        assert!(result.is_err(), "malformed datagram is dropped silently");

        shutdown_tx.send(()).unwrap();
        serve_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_until_stops_promptly_on_shutdown_signal() {
        let resolver = resolver_with(FixedBackend(answer_with_a(
            "example.com",
            0,
            std::net::Ipv4Addr::new(203, 0, 113, 4),
        )));
        let server = ServerBuilder::new(resolver)
            .udp_addr("127.0.0.1:0".parse().unwrap())
            .tcp_addr("127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .expect("binds udp and tcp");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), serve_task)
            .await
            .expect("serve_until returns promptly after shutdown signal, no hang");
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn serve_until_stops_on_shutdown_even_with_no_addresses_bound() {
        let resolver = resolver_with(FixedBackend(answer_with_a(
            "example.com",
            0,
            std::net::Ipv4Addr::new(203, 0, 113, 5),
        )));
        let server = ServerBuilder::new(resolver)
            .bind()
            .await
            .expect("binds zero addresses without error");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let serve_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), serve_task)
            .await
            .expect("serve_until with no bound sockets still returns on shutdown");
        assert!(result.unwrap().is_ok());
    }

    #[cfg(feature = "dot")]
    mod dot_tests {
        use super::*;
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls_pki_types::ServerName;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};

        /// Generates a self-signed loopback certificate and matching
        /// server/client `rustls` configs, mirroring
        /// `upstream::dot::tests::self_signed_fixture` — fully offline and
        /// deterministic per `@.claude/rules/ci.md`.
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

        async fn dot_query(
            connector: &TlsConnector,
            server_name: ServerName<'static>,
            addr: SocketAddr,
            query: &Message,
        ) -> Message {
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

            let payload = query.encode().unwrap();
            let len: u16 = payload.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(&payload);
            tls_stream.write_all(&framed).await.unwrap();

            let mut len_buf = [0u8; 2];
            tls_stream.read_exact(&mut len_buf).await.unwrap();
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response_buf = vec![0u8; response_len];
            tls_stream.read_exact(&mut response_buf).await.unwrap();
            Message::decode(&response_buf).unwrap()
        }

        #[tokio::test]
        async fn dot_round_trip_success() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 10),
            )));
            let server = ServerBuilder::new(resolver)
                .dot_addr("127.0.0.1:0".parse().unwrap(), Arc::new(server_config))
                .bind()
                .await
                .expect("binds dot");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.dot_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let query = query_for("example.com", 21);
            let response = dot_query(&connector, server_name, addr, &query).await;
            assert!(response.header.qr);
            assert_eq!(response.header.id, 21);
            assert_eq!(response.header.rcode, Rcode::NoError);
            assert_eq!(response.answers.len(), 1);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn dot_multiple_queries_over_one_tls_connection() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 11),
            )));
            let server = ServerBuilder::new(resolver)
                .dot_addr("127.0.0.1:0".parse().unwrap(), Arc::new(server_config))
                .bind()
                .await
                .expect("binds dot");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.dot_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

            for id in [1u16, 2u16, 3u16] {
                let query = query_for(&format!("q{id}.example.com"), id);
                let payload = query.encode().unwrap();
                let len: u16 = payload.len().try_into().unwrap();
                let mut framed = Vec::new();
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&payload);
                tls_stream.write_all(&framed).await.unwrap();

                let mut len_buf = [0u8; 2];
                tls_stream.read_exact(&mut len_buf).await.unwrap();
                let response_len = u16::from_be_bytes(len_buf) as usize;
                let mut response_buf = vec![0u8; response_len];
                tls_stream.read_exact(&mut response_buf).await.unwrap();
                let response = Message::decode(&response_buf).unwrap();
                assert!(response.header.qr);
                assert_eq!(response.header.id, id);
            }

            drop(tls_stream);
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn dot_servfail_synthesized_on_resolver_error() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FailingBackend);
            let server = ServerBuilder::new(resolver)
                .dot_addr("127.0.0.1:0".parse().unwrap(), Arc::new(server_config))
                .bind()
                .await
                .expect("binds dot");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.dot_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let query = query_for("nope.example.com", 33);
            let response = dot_query(&connector, server_name, addr, &query).await;
            assert_eq!(response.header.rcode, Rcode::ServFail);
            assert_eq!(response.header.id, 33);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }
    }

    #[cfg(feature = "doh")]
    mod doh_tests {
        use super::*;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use quinn::ClientConfig as QuinnClientConfig;
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};

        /// Generates a self-signed loopback certificate and matching
        /// server/client `rustls` configs, mirroring
        /// `dot_tests::self_signed_fixture`/`upstream::doh::tests::
        /// self_signed_fixture` — fully offline and deterministic per
        /// `@.claude/rules/ci.md`.
        fn self_signed_fixture() -> (ServerConfig, ClientConfig, ServerName<'static>) {
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert_der: CertificateDer<'static> = cert.der().clone();
            let key_der: PrivateKeyDer<'static> =
                PrivateKeyDer::try_from(signing_key.serialize_der()).unwrap();

            let mut server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key_der)
                .unwrap();
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let mut roots = RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let client_config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();

            let server_name = ServerName::try_from("localhost").unwrap();
            (server_config, client_config, server_name)
        }

        fn http3_server_config(server_config: ServerConfig) -> quinn::ServerConfig {
            let crypto = QuicServerConfig::try_from(Arc::new(server_config)).unwrap();
            quinn::ServerConfig::with_crypto(Arc::new(crypto))
        }

        async fn send_http3_request(
            client_config: ClientConfig,
            addr: SocketAddr,
            request: http::Request<()>,
            body: Bytes,
        ) -> (u16, Vec<u8>) {
            let mut client_config = client_config;
            client_config.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = QuicClientConfig::try_from(Arc::new(client_config)).unwrap();
            let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
            let connection = endpoint
                .connect_with(QuinnClientConfig::new(Arc::new(crypto)), addr, "localhost")
                .unwrap()
                .await
                .unwrap();
            let data = connection
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .unwrap();
            assert_eq!(data.protocol.as_deref(), Some(b"h3".as_slice()));
            let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let driver_task = tokio::spawn(async move { driver.wait_idle().await });
            let mut stream = sender.send_request(request).await.unwrap();
            if !body.is_empty() {
                stream.send_data(body).await.unwrap();
            }
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            let status = response.status().as_u16();
            let mut response_body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.unwrap() {
                response_body.extend_from_slice(chunk.chunk());
            }
            endpoint.close(0u32.into(), b"request complete");
            driver_task.abort();
            (status, response_body)
        }

        fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        }

        /// A minimal manual HTTP/1.1-over-TLS client used in the test's
        /// client role, using manual HTTP/1.1 request construction.
        /// Sends `request_line`/`headers`/`body` and returns
        /// `(status_code, body_bytes)`.
        async fn send_http_request(
            connector: &TlsConnector,
            server_name: ServerName<'static>,
            addr: SocketAddr,
            request_line: &str,
            extra_headers: &[(&str, String)],
            body: &[u8],
        ) -> (u16, Vec<u8>) {
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

            let mut request = format!("{request_line}\r\nhost: localhost\r\n");
            for (name, value) in extra_headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
            if !body.is_empty() {
                request.push_str(&format!("content-length: {}\r\n", body.len()));
            }
            request.push_str("connection: close\r\n\r\n");

            tls_stream.write_all(request.as_bytes()).await.unwrap();
            tls_stream.write_all(body).await.unwrap();

            let mut buf = Vec::new();
            tls_stream.read_to_end(&mut buf).await.unwrap();

            let header_end =
                find_subslice(&buf, b"\r\n\r\n").expect("response has a header/body separator");
            let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
            let status_line = headers.lines().next().unwrap();
            let status: u16 = status_line
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();

            let body_start = header_end + 4;
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
                .unwrap_or(buf.len().saturating_sub(body_start));

            (
                status,
                buf[body_start..body_start + content_length].to_vec(),
            )
        }

        /// Sends one HTTP/2 DoH request after requiring TLS ALPN to select
        /// `h2`; returns the HTTP status and response body.
        async fn send_http2_request(
            client_config: ClientConfig,
            server_name: ServerName<'static>,
            addr: SocketAddr,
            request: hyper::Request<Full<Bytes>>,
        ) -> (u16, Vec<u8>) {
            let mut client_config = client_config;
            client_config.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(client_config));
            let tcp_stream = TcpStream::connect(addr).await.unwrap();
            let tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice())
            );

            let (mut sender, connection) =
                hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(tls_stream))
                    .await
                    .unwrap();
            let connection_task = tokio::spawn(async move { connection.await.unwrap() });
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.version(), hyper::Version::HTTP_2);
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec();
            drop(sender);
            connection_task.await.unwrap();
            (status, body)
        }

        #[tokio::test]
        async fn doh_get_round_trip_success() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 30),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .expect("binds doh");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let query = query_for("example.com", 41);
            let payload = query.encode().unwrap();
            let encoded = URL_SAFE_NO_PAD.encode(&payload);
            let (status, body) = send_http_request(
                &connector,
                server_name,
                addr,
                &format!("GET /dns-query?dns={encoded} HTTP/1.1"),
                &[],
                &[],
            )
            .await;
            assert_eq!(status, 200);
            let response = Message::decode(&body).unwrap();
            assert!(response.header.qr);
            assert_eq!(response.header.id, 41);
            assert_eq!(response.header.rcode, Rcode::NoError);
            assert_eq!(response.answers.len(), 1);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_post_round_trip_success() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 31),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .expect("binds doh");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let query = query_for("example.com", 42);
            let payload = query.encode().unwrap();
            let (status, body) = send_http_request(
                &connector,
                server_name,
                addr,
                "POST /dns-query HTTP/1.1",
                &[("content-type", "application/dns-message".to_string())],
                &payload,
            )
            .await;
            assert_eq!(status, 200);
            let response = Message::decode(&body).unwrap();
            assert!(response.header.qr);
            assert_eq!(response.header.id, 42);
            assert_eq!(response.header.rcode, Rcode::NoError);
            assert_eq!(response.answers.len(), 1);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_get_round_trip_success_over_http2() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 34),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let query = query_for("example.com", 44);
            let encoded = URL_SAFE_NO_PAD.encode(query.encode().unwrap());
            let request = hyper::Request::builder()
                .method(hyper::Method::GET)
                .uri(format!("https://localhost/dns-query?dns={encoded}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let (status, body) =
                send_http2_request(client_config, server_name, addr, request).await;
            assert_eq!(status, 200);
            assert_eq!(Message::decode(&body).unwrap().header.id, 44);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_post_round_trip_success_over_http2() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 35),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let query = query_for("example.com", 45);
            let request = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri("https://localhost/dns-query")
                .header("content-type", "application/dns-message")
                .body(Full::new(Bytes::from(query.encode().unwrap())))
                .unwrap();
            let (status, body) =
                send_http2_request(client_config, server_name, addr, request).await;
            assert_eq!(status, 200);
            assert_eq!(Message::decode(&body).unwrap().header.id, 45);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh3_get_round_trip_success() {
            let (mut server_config, client_config, _server_name) = self_signed_fixture();
            server_config.alpn_protocols = vec![b"h3".to_vec()];
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 36),
            )));
            let server = ServerBuilder::new(resolver)
                .doh3_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    http3_server_config(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let addr = server.doh3_endpoints[0].0.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let query = query_for("example.com", 46);
            let encoded = URL_SAFE_NO_PAD.encode(query.encode().unwrap());
            let request = http::Request::builder()
                .method(http::Method::GET)
                .uri(format!("https://localhost/dns-query?dns={encoded}"))
                .body(())
                .unwrap();
            let (status, body) =
                send_http3_request(client_config, addr, request, Bytes::new()).await;
            assert_eq!(status, 200);
            assert_eq!(Message::decode(&body).unwrap().header.id, 46);
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh3_post_round_trip_success() {
            let (mut server_config, client_config, _server_name) = self_signed_fixture();
            server_config.alpn_protocols = vec![b"h3".to_vec()];
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 37),
            )));
            let server = ServerBuilder::new(resolver)
                .doh3_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    http3_server_config(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let addr = server.doh3_endpoints[0].0.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let query = query_for("example.com", 47);
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://localhost/dns-query")
                .header("content-type", "application/dns-message")
                .body(())
                .unwrap();
            let (status, body) = send_http3_request(
                client_config,
                addr,
                request,
                Bytes::from(query.encode().unwrap()),
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(Message::decode(&body).unwrap().header.id, 47);
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh3_malformed_get_query_param_is_http_400() {
            let (mut server_config, client_config, _server_name) = self_signed_fixture();
            server_config.alpn_protocols = vec![b"h3".to_vec()];
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 38),
            )));
            let server = ServerBuilder::new(resolver)
                .doh3_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    http3_server_config(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let addr = server.doh3_endpoints[0].0.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let request = http::Request::builder()
                .method(http::Method::GET)
                .uri("https://localhost/dns-query?dns=@@@not-base64@@@")
                .body(())
                .unwrap();
            let (status, body) =
                send_http3_request(client_config, addr, request, Bytes::new()).await;
            assert_eq!(status, 400);
            assert!(body.is_empty());
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh3_wrong_path_is_http_404() {
            let (mut server_config, client_config, _server_name) = self_signed_fixture();
            server_config.alpn_protocols = vec![b"h3".to_vec()];
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 39),
            )));
            let server = ServerBuilder::new(resolver)
                .doh3_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    http3_server_config(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let addr = server.doh3_endpoints[0].0.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let query = query_for("example.com", 48);
            let encoded = URL_SAFE_NO_PAD.encode(query.encode().unwrap());
            let request = http::Request::builder()
                .method(http::Method::GET)
                .uri(format!("https://localhost/wrong-path?dns={encoded}"))
                .body(())
                .unwrap();
            let (status, body) =
                send_http3_request(client_config, addr, request, Bytes::new()).await;
            assert_eq!(status, 404);
            assert!(body.is_empty());
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh3_servfail_is_dns_response_not_http_error() {
            let (mut server_config, client_config, _server_name) = self_signed_fixture();
            server_config.alpn_protocols = vec![b"h3".to_vec()];
            let server = ServerBuilder::new(resolver_with(FailingBackend))
                .doh3_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    http3_server_config(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .unwrap();
            let addr = server.doh3_endpoints[0].0.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            let query = query_for("example.com", 49);
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri("https://localhost/dns-query")
                .body(())
                .unwrap();
            let (status, body) = send_http3_request(
                client_config,
                addr,
                request,
                Bytes::from(query.encode().unwrap()),
            )
            .await;
            assert_eq!(status, 200);
            let response = Message::decode(&body).unwrap();
            assert_eq!(response.header.id, 49);
            assert_eq!(response.header.rcode, Rcode::ServFail);
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_servfail_synthesized_on_resolver_error() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FailingBackend);
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .expect("binds doh");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let query = query_for("nope.example.com", 43);
            let payload = query.encode().unwrap();
            let (status, body) = send_http_request(
                &connector,
                server_name,
                addr,
                "POST /dns-query HTTP/1.1",
                &[("content-type", "application/dns-message".to_string())],
                &payload,
            )
            .await;
            assert_eq!(status, 200);
            let response = Message::decode(&body).unwrap();
            assert_eq!(response.header.rcode, Rcode::ServFail);
            assert_eq!(response.header.id, 43);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_malformed_get_query_param_is_http_400() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 32),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .expect("binds doh");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            // `@` is a legal URI query character (RFC 3986) but not part of
            // the base64url alphabet, so this is a syntactically valid HTTP
            // request whose `dns` parameter fails to decode.
            let (status, _body) = send_http_request(
                &connector,
                server_name,
                addr,
                "GET /dns-query?dns=@@@not-base64@@@ HTTP/1.1",
                &[],
                &[],
            )
            .await;
            assert_eq!(status, 400);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doh_wrong_path_is_http_404() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 33),
            )));
            let server = ServerBuilder::new(resolver)
                .doh_addr(
                    "127.0.0.1:0".parse().unwrap(),
                    Arc::new(server_config),
                    DohListenerConfig::default(),
                )
                .bind()
                .await
                .expect("binds doh");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doh_listeners[0].0.local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let connector = TlsConnector::from(Arc::new(client_config));
            let (status, _body) = send_http_request(
                &connector,
                server_name,
                addr,
                "GET /wrong-path HTTP/1.1",
                &[],
                &[],
            )
            .await;
            assert_eq!(status, 404);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }
    }

    #[cfg(feature = "doq")]
    mod doq_tests {
        use super::*;
        use quinn::ClientConfig as QuinnClientConfig;
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::{
            ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig,
        };
        use rustls_pki_types::ServerName;

        /// The ALPN protocol identifier for DNS-over-QUIC (RFC 9250
        /// §4.1.1), duplicated from `upstream::doq`'s private constant since
        /// it is not exported — matches that module's own value.
        const DOQ_ALPN: &[u8] = b"doq";

        /// Generates a self-signed loopback certificate and matching
        /// `quinn`/`rustls` server config plus a trusting `quinn` client
        /// config (ALPN `doq`), mirroring `upstream::doq::tests::
        /// self_signed_fixture` — fully offline and deterministic per
        /// `@.claude/rules/ci.md`.
        fn self_signed_fixture() -> (quinn::ServerConfig, QuinnClientConfig, ServerName<'static>) {
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
            let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

            let mut roots = RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let mut rustls_client_config = RustlsClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            rustls_client_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];
            let quic_client_config: QuicClientConfig =
                rustls_client_config.try_into().expect("valid tls config");
            let client_config = QuinnClientConfig::new(Arc::new(quic_client_config));

            let server_name = ServerName::try_from("localhost").unwrap();
            (server_config, client_config, server_name)
        }

        /// Opens a fresh QUIC connection and bidirectional stream, sends one
        /// framed query, and reads back one framed response — mirroring
        /// `DoqBackend::resolve`'s own client-side sequence.
        async fn doq_query(
            client_endpoint: &quinn::Endpoint,
            client_config: QuinnClientConfig,
            server_name: ServerName<'static>,
            addr: SocketAddr,
            query: &Message,
        ) -> Message {
            let connecting = client_endpoint
                .connect_with(client_config, addr, server_name.to_str().as_ref())
                .unwrap();
            let connection = connecting.await.unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();

            let payload = query.encode().unwrap();
            let len: u16 = payload.len().try_into().unwrap();
            let mut framed = Vec::new();
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(&payload);
            send.write_all(&framed).await.unwrap();
            let _ = send.finish();

            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf).await.unwrap();
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response_buf = vec![0u8; response_len];
            recv.read_exact(&mut response_buf).await.unwrap();
            Message::decode(&response_buf).unwrap()
        }

        fn client_endpoint() -> quinn::Endpoint {
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap()
        }

        #[tokio::test]
        async fn doq_round_trip_success() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 20),
            )));
            let server = ServerBuilder::new(resolver)
                .doq_addr("127.0.0.1:0".parse().unwrap(), server_config)
                .bind()
                .await
                .expect("binds doq");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doq_endpoints[0].local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let client_endpoint = client_endpoint();
            let query = query_for("example.com", 21);
            let response =
                doq_query(&client_endpoint, client_config, server_name, addr, &query).await;
            assert!(response.header.qr);
            assert_eq!(response.header.id, 21);
            assert_eq!(response.header.rcode, Rcode::NoError);
            assert_eq!(response.answers.len(), 1);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doq_multiple_queries_over_one_quic_connection() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FixedBackend(answer_with_a(
                "example.com",
                0,
                std::net::Ipv4Addr::new(203, 0, 113, 21),
            )));
            let server = ServerBuilder::new(resolver)
                .doq_addr("127.0.0.1:0".parse().unwrap(), server_config)
                .bind()
                .await
                .expect("binds doq");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doq_endpoints[0].local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let client_endpoint = client_endpoint();
            let connecting = client_endpoint
                .connect_with(client_config, addr, server_name.to_str().as_ref())
                .unwrap();
            let connection = connecting.await.unwrap();

            // RFC 9250 §4.2: each query gets its own bidirectional stream on
            // the same QUIC connection, unlike DoT/TCP's shared-stream loop.
            for id in [1u16, 2u16, 3u16] {
                let query = query_for(&format!("q{id}.example.com"), id);
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                let payload = query.encode().unwrap();
                let len: u16 = payload.len().try_into().unwrap();
                let mut framed = Vec::new();
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&payload);
                send.write_all(&framed).await.unwrap();
                let _ = send.finish();

                let mut len_buf = [0u8; 2];
                recv.read_exact(&mut len_buf).await.unwrap();
                let response_len = u16::from_be_bytes(len_buf) as usize;
                let mut response_buf = vec![0u8; response_len];
                recv.read_exact(&mut response_buf).await.unwrap();
                let response = Message::decode(&response_buf).unwrap();
                assert!(response.header.qr);
                assert_eq!(response.header.id, id);
            }

            drop(connection);
            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn doq_servfail_synthesized_on_resolver_error() {
            let (server_config, client_config, server_name) = self_signed_fixture();
            let resolver = resolver_with(FailingBackend);
            let server = ServerBuilder::new(resolver)
                .doq_addr("127.0.0.1:0".parse().unwrap(), server_config)
                .bind()
                .await
                .expect("binds doq");

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let addr = server.doq_endpoints[0].local_addr().unwrap();
            let serve_task = tokio::spawn(async move {
                server
                    .serve_until(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });

            let client_endpoint = client_endpoint();
            let query = query_for("nope.example.com", 33);
            let response =
                doq_query(&client_endpoint, client_config, server_name, addr, &query).await;
            assert_eq!(response.header.rcode, Rcode::ServFail);
            assert_eq!(response.header.id, 33);

            shutdown_tx.send(()).unwrap();
            serve_task.await.unwrap().unwrap();
        }
    }
}
