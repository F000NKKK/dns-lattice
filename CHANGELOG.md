# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- New public `dns_lattice::fakeip` module: `FakeIpPool` configures inclusive
  IPv4 and/or IPv6 ranges, deterministically allocates or reuses one
  synthetic address per DNS name, and reverse-resolves active mappings.
  Each family uses a family-salted FNV-1a candidate, circular probing, and
  independent LRU eviction when full. It is a synchronous, concurrent,
  data-only pool: DNS answer/PTR synthesis, TTL expiry, persistence,
  and resolver/server integration remain out of scope.
- New typed `dns_lattice_core::Error` variants for invalid/unconfigured Fake
  IP pool configuration and allocation in a disabled family.

## [0.3.0] - 2026-08-13

- The default-off `doh` feature now enables ALPN-negotiated HTTP/1.1 and
  HTTP/2 over TCP/TLS 1.2 or 1.3 for both `DohBackend` and
  `ServerBuilder::doh_addr`. GET and POST are covered end-to-end on both
  HTTP versions; a dual-protocol inbound deployment supplies `h2` and
  `http/1.1` in its `rustls::ServerConfig`.
- `Doh3Backend`/`Doh3BackendConfig` and `ServerBuilder::doh3_addr` add
  RFC 9114 HTTP/3 over QUIC/UDP with ALPN `h3`. HTTP/3 uses TLS 1.3 as
  required by QUIC; existing TCP HTTP/1.1/HTTP/2 DoH APIs remain available
  for TLS 1.2 legacy compatibility. HTTP/3 now preserves the public error
  boundary for QUIC TLS alerts (`Error::Tls`), HTTP/3/transport failures
  (`Error::Transport`), and expired request bounds (`Error::Timeout`).

- DoT now classifies an underlying TCP connection close before a TLS session
  exists as `Error::Transport`; only errors reported by `rustls` during TLS
  negotiation or certificate verification are `Error::Tls`. The upstream
  TCP, DoT, and DoH transport-failure tests now use a controlled loopback
  peer-close fixture instead of relying on platform-specific behavior of a
  TCP connection to a UDP-bound port.

- Stage 0.3 Track A (upstream transport, part 1): new public, async
  `dns_lattice::upstream` module — `UpstreamBackend` trait (replacing
  stage 0.2's crate-private, synchronous `engine::UpstreamBackend`,
  ADR-0009) plus baseline `UdpBackend`/`TcpBackend` implementations over
  `tokio`. No EDNS0/OPT support yet; `UdpBackend` falls back to a TCP query
  when a response's `TC` bit is set. See ADR-0011 (`DL-A-12`) for the full
  design rationale.
- **Breaking:** `Resolver::resolve` is now `async fn` and must be called
  from inside a `tokio` runtime; `ResolverBuilder::backend` now stores an
  ordered list of backends per upstream group (only the first is used this
  stage — later tracks add failover across the rest).
- New `dns_lattice_core::Error` variants: `Timeout` and `Transport(String)`,
  produced by the new UDP/TCP backends.
- Stage 0.3 Track B (upstream transport, part 2): two new default-off Cargo
  features on `dns-lattice`, `dot` and `doh`. `dot` adds `DotBackend`/
  `DotBackendConfig` (DNS-over-TLS, RFC 7858) over `rustls`/`tokio-rustls`;
  `doh` adds `DohBackend`/`DohBackendConfig`/`DohMethod` (DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats) over `hyper`/`hyper-rustls`. Both
  are independent and additive to the baseline UDP/TCP build, which keeps
  zero TLS/HTTP dependency weight unless explicitly opted into. New
  `dns_lattice_core::Error::Tls(String)` variant for TLS handshake/
  certificate/hostname-verification failures, distinct from `Transport`.
  See ADR-0012 (`DL-A-13`) for the full design rationale.
- Stage 0.3 Track C (upstream transport, part 3): new default-off `doq`
  Cargo feature on `dns-lattice` adding `DoqBackend`/`DoqBackendConfig`
  (DNS-over-QUIC, RFC 9250) over `quinn` (TLS 1.3 embedded in QUIC via
  `rustls`, sharing the workspace's `aws-lc-rs` crypto provider with
  `dot`/`doh`). Independent of `dot`/`doh`; opens a fresh QUIC connection
  per query in this stage (no pooling/reuse), one bidirectional stream per
  query, no 0-RTT. No new `dns_lattice_core::Error` variant — reuses
  `Tls`/`Transport` on the same boundary as `dot`/`doh`. See ADR-0013
  (`DL-A-14`) for the full design rationale.
- Stage 0.3 Track D (fallback/failover across upstreams within a group):
  `Resolver::resolve` now tries every backend registered for a matched
  upstream group in registration order instead of only the first — a
  backend failing with `Error::Timeout`, `Error::Transport`, or
  `Error::Tls` falls over to the next backend in the group; the first
  success is cached and returned as before. Once every backend in a group
  has failed, the last attempted backend's error is propagated as-is (no
  new `Error` variant, no synthesized answer, not cached) — this is a
  purely internal behavioral change, `Resolver::resolve`'s signature is
  unchanged. See ADR-0014 (`DL-A-15`) for the full design rationale.
- Stage 0.3 Track E (inbound server listener, UDP/TCP baseline): new public
  `dns_lattice::server` module — `Server`/`ServerBuilder`, an embeddable
  DNS server engine built on `engine::Resolver`. `ServerBuilder::new` takes
  a shared `Arc<Resolver>`; `udp_addr`/`tcp_addr` configure one or more
  listen addresses; `bind` performs the actual socket binds; `serve`/
  `serve_until` run the UDP receive loop and TCP accept loop concurrently
  (one `tokio` task per datagram, one per TCP connection looping over
  multiple length-prefixed queries per RFC 1035 §4.2.2) until dropped or a
  caller-supplied shutdown future resolves. Oversized UDP answers are
  truncated with `TC=1` set at the existing 512-byte RFC 1035 §4.2.1
  boundary; a `Resolver::resolve` error is answered with a synthesized
  `Rcode::ServFail` response rather than dropped or left to crash the
  listener, while an inbound message that fails to decode at all is
  dropped (no reliable id/question to answer with). Binding a privileged
  port stays the composing application's responsibility, not this crate's.
  Internally, `upstream::framed_query` is now implemented in terms of two
  new crate-private `read_framed`/`write_framed` halves, shared unchanged
  by both `upstream` (client role) and `server` (listener role) — no
  public API change to `upstream`. This is the first slice fulfilling the
  "embeddable DNS server engine" goal named in the architecture doc;
  DoT/DoH/DoQ inbound listeners are deferred to follow-up work behind the
  same `dot`/`doh`/`doq` Cargo features their `upstream` counterparts use.
  See ADR-0015 (`DL-A-16`) for the full design rationale.
- Stage 0.3 Track E (inbound server listener, DoT): new
  `ServerBuilder::dot_addr(SocketAddr, Arc<rustls::ServerConfig>)` method,
  behind the existing default-off `dot` Cargo feature, additive to the
  UDP/TCP baseline. Binds a TCP listener, TLS-accepts each connection via
  `tokio_rustls::TlsAcceptor` (caller-supplied `rustls::ServerConfig` — this
  crate does not source certificate material), then reuses the same
  length-prefixed read/write loop the baseline TCP listener uses once the
  handshake completes, so a DoT connection can carry multiple back-to-back
  queries exactly like plain TCP; a TLS handshake failure ends that
  connection without a response, matching the existing undecodable-message
  policy. `Resolver::resolve` errors are still answered with a synthesized
  `Rcode::ServFail`, unchanged from the baseline. No existing `ServerBuilder`/
  `Server` public method signature changes. See ADR-0016 (`DL-A-17`) for the
  full design rationale (also covers deferred DoH/DoQ listener design).
- Stage 0.3 Track E (inbound server listener, DoQ): new
  `ServerBuilder::doq_addr(SocketAddr, quinn::ServerConfig)` method, behind
  the existing default-off `doq` Cargo feature, additive to the UDP/TCP/DoT
  listeners. Builds a `quinn::Endpoint` in server mode (ALPN `doq`, RFC
  9250), accepts one fresh bidirectional QUIC stream per query, and reuses
  the same `read_framed`/`write_framed` framing helpers `upstream`'s
  `DoqBackend` already uses on the client side. `Resolver::resolve` errors
  are still answered with a synthesized `Rcode::ServFail`, unchanged from
  the baseline. No existing `ServerBuilder`/`Server` public method
  signature changes. See ADR-0016 (`DL-A-17`) for the full design
  rationale.
- Stage 0.3 Track E (inbound server listener, DoH) — the final Track E
  slice, completing Stage 0.3: new `ServerBuilder::doh_addr(SocketAddr,
  Arc<rustls::ServerConfig>, DohListenerConfig)` method and new public
  `DohListenerConfig` type (RFC 8484 request path, defaulting to
  `/dns-query`), behind the existing default-off `doh` Cargo feature,
  additive to the UDP/TCP/DoT/DoQ listeners. Binds a TCP listener,
  TLS-accepts each connection identically to `dot_addr`, then serves
  ALPN-negotiated HTTP/1.1 or HTTP/2 via `hyper_util::server::conn::auto::Builder`, parsing RFC 8484
  GET (`?dns=` base64url query parameter) and POST (`application/
  dns-message` body) requests. A path mismatch responds HTTP 404; an
  unsupported method or a request whose bytes cannot be extracted/decoded
  responds HTTP 400 before `Message::decode` is ever reached; everything
  that decodes responds HTTP 200 with an `application/dns-message` body,
  with `Resolver::resolve` errors still answered as a synthesized
  `Rcode::ServFail` inside that body (not an HTTP error status), matching
  every other transport's error policy adapted to HTTP's request/response
  model. `dns-lattice`'s `doh` Cargo feature now additionally requests
  `hyper`'s `server` feature and `hyper-util`'s `server`/`server-auto`
  features on its existing dependencies (no new crate). No existing
  `ServerBuilder`/`Server` public method signature changes. This closes out
  Track E and Stage 0.3 in full — every planned UDP/TCP/DoT/DoH/DoQ
  upstream backend and inbound listener for this stage has now landed. See
  ADR-0016 for the full design rationale.

## [0.2.0] - 2026-08-02

- Stage 0.2 (resolver engine and static split DNS): `dns-lattice`'s new
  `engine` module (`Resolver`, `ResolverBuilder`) — in-process
  construct/resolve, static split-DNS routing via `SplitDnsPolicy`, a new
  `dns_lattice_core::Error::NoRoute` variant for unroutable queries, and an
  in-memory TTL-respecting answer cache including RFC 2308 negative
  caching. No real network transport yet.

## [0.1.0] - 2026-08-02

- Repository bootstrap: workflow, policies, and packaging scaffolding.
- Stage 0.1 (core model): `dns-lattice-core` (shared `Error`/`Result`) and
  `dns-lattice-model` (DNS message, zone/domain matcher, split-DNS policy
  types) crates, with `dns-lattice` as the facade crate re-exporting them.
