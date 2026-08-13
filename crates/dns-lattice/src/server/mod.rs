//! Inbound DNS server listener: binds UDP/TCP (baseline) and hands decoded
//! queries to [`crate::engine::Resolver`], fulfilling the embeddable-
//! server-engine goal named in `ARCHITECTURE.md`.
//!
//! Per ADR-0015 (`DL-A-16`), this module is scoped to the UDP/TCP baseline
//! only in this stage; DoT/DoH/DoQ inbound listeners are separate follow-up
//! work behind the same `dot`/`doh`/`doq` Cargo features their `upstream`
//! counterparts already use.
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
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::Resolver;
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
/// into a fallible `bind` step (per ADR-0015, `DL-A-16` decision 2) since
/// binding a socket is the first point actual I/O/OS errors can occur.
pub struct ServerBuilder {
    resolver: Arc<Resolver>,
    udp_addrs: Vec<SocketAddr>,
    tcp_addrs: Vec<SocketAddr>,
}

impl ServerBuilder {
    /// Starts building a server that answers queries via `resolver`.
    ///
    /// Takes `Arc<Resolver>` (not `Resolver` by value or `&Resolver`)
    /// because the resolver must outlive, and be shared across, every
    /// concurrently spawned per-connection/per-datagram `tokio::task`
    /// (ADR-0015, `DL-A-16` decision 2 and its "alternatives considered").
    pub fn new(resolver: Arc<Resolver>) -> Self {
        ServerBuilder {
            resolver,
            udp_addrs: Vec::new(),
            tcp_addrs: Vec::new(),
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

    /// Binds every configured UDP/TCP address and returns the bound
    /// [`Server`], ready to [`Server::serve`].
    ///
    /// Binding a privileged port (e.g. `0.0.0.0:53` on Unix) is the
    /// composing application's responsibility, not this crate's (`DL-19`'s
    /// stated non-goal) — a permission-denied OS error surfaces here as an
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

        Ok(Server {
            resolver: self.resolver,
            udp_sockets,
            tcp_listeners,
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
/// per received datagram (ADR-0015, `DL-A-16` decision 3) so one slow
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
/// accepted connection (ADR-0015, `DL-A-16` decision 4), each looping over
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

/// Serves one accepted TCP connection: repeatedly reads a length-prefixed
/// query and writes back a length-prefixed response until the connection
/// closes or a read/write error occurs, so a single connection can carry
/// multiple back-to-back queries (RFC 1035 §4.2.2).
async fn handle_tcp_connection(mut stream: TcpStream, resolver: &Resolver) {
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
/// question section (ADR-0015, `DL-A-16` decision 6), used whenever
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
        Class, Header, Name, Opcode, Question, RData, RecordType, ResourceRecord, SplitDnsPolicy,
        UpstreamGroupId,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

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
}
