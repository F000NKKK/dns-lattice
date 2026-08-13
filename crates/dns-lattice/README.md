# dns-lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## What it provides

- `dns-lattice-model`'s DNS message model (`Message`, `Header`, `Question`,
  `ResourceRecord`, `RData`), zone/domain matcher (`DomainPattern`,
  `DomainMatcher`), and split-DNS policy types (`SplitDnsPolicy`), re-exported
  through this facade crate.
- `dns-lattice-core`'s `Error`/`Result` pair.
- An in-process resolver entry point (`Resolver`, `ResolverBuilder`): route
  one query through a `SplitDnsPolicy` to an upstream group, then try that
  group's registered backends in registration order — a backend failing
  with a timeout/transport/TLS error falls over to the next backend in the
  group, and the first success is cached in memory (TTL-respecting, with
  RFC 2308 negative caching) so a repeated query is served without
  re-querying the backend. Once every backend in the group has failed, the
  last attempted backend's error is returned as-is. `Resolver::resolve` is
  `async fn` and must be called from inside a `tokio` runtime.
- A public, async `upstream` module (`UpstreamBackend` trait, `UdpBackend`,
  `TcpBackend`): baseline UDP and TCP upstream transports, no EDNS0/OPT
  support yet (`UdpBackend` falls back to a TCP query when a response's
  `TC` bit is set).
- Three opt-in, default-off Cargo features adding encrypted upstream
  transports to the same `upstream` module: `dot` (`DotBackend`/
  `DotBackendConfig`, DNS-over-TLS, RFC 7858, over `rustls`/`tokio-rustls`),
  `doh` (`DohBackend`/`DohBackendConfig`/`DohMethod`, DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats, over `hyper`/`hyper-rustls`), and
  `doq` (`DoqBackend`/`DoqBackendConfig`, DNS-over-QUIC, RFC 9250, over
  `quinn`, with TLS 1.3 embedded in QUIC via `rustls`). `doq` opens a fresh
  QUIC connection per query in this stage — no connection pooling/reuse
  yet.
- A public, async `server` module (`Server`, `ServerBuilder`): an
  embeddable inbound UDP/TCP DNS listener over a shared `Arc<Resolver>`.
  `ServerBuilder::new(resolver)` plus `udp_addr`/`tcp_addr` configure one or
  more listen addresses, `bind` performs the actual socket binds, and
  `serve`/`serve_until` run the UDP receive loop and TCP accept loop
  concurrently — one `tokio` task per received UDP datagram, one per
  accepted TCP connection (looping over multiple RFC 1035 §4.2.2
  length-prefixed queries per connection). Oversized UDP answers are
  truncated with `TC=1` set at the existing 512-byte boundary; a
  `Resolver::resolve` error is answered with a synthesized
  `Rcode::ServFail` response instead of being dropped or crashing the
  listener. Behind the default-off `dot` Cargo feature,
  `ServerBuilder::dot_addr(addr, tls_config)` adds an inbound DNS-over-TLS
  (RFC 7858) listener: it TLS-accepts each connection via
  `tokio_rustls::TlsAcceptor` (caller-supplied `rustls::ServerConfig`) and
  then reuses the exact same length-prefixed read/write loop as the plain
  TCP listener. Behind the default-off `doq` Cargo feature,
  `ServerBuilder::doq_addr(addr, server_config)` adds an inbound
  DNS-over-QUIC (RFC 9250) listener: a `quinn::Endpoint` in server mode
  (ALPN `doq`) answers one query per accepted bidirectional stream,
  reusing the same framing helpers as `DoqBackend`'s client side. Behind
  the default-off `doh` Cargo feature, `ServerBuilder::doh_addr(addr,
  tls_config, config)` adds an inbound DNS-over-HTTPS (RFC 8484) listener:
  it TLS-accepts each connection like `dot_addr`, then serves the
  ALPN-negotiated HTTP/1.1 or HTTP/2 protocol via `hyper_util`'s
  protocol-detecting server builder, parsing RFC 8484 GET (`?dns=`
  base64url query parameter) and POST (`application/dns-message` body)
  requests. A dual-protocol deployment configures `h2` and `http/1.1` in
  its `rustls::ServerConfig` ALPN list. `config` (a `DohListenerConfig`, defaulting to the
  `/dns-query` path) selects which URI path the listener answers; any
  other path gets HTTP 404, an unsupported method or undecodable request
  gets HTTP 400, and everything else is answered HTTP 200 with an
  `application/dns-message` body — including a synthesized `Rcode::ServFail`
  on a resolver error, matching every other transport's error policy.

Fake IP and dynamic routing hook capabilities are planned for later
stages; see `ROADMAP.md` in the repository root.

## Feature/platform constraints

- Default build: no Cargo features enabled. Carries no TLS/HTTP dependency
  weight — only `dns-lattice-core`, `dns-lattice-model`, `async-trait`, and
  `tokio` (with `net`/`time`/`rt`/`macros`/`io-util` only).
- `dot` feature: adds `rustls`, `rustls-pki-types`, `tokio-rustls`, and
  `webpki-roots` as dependencies. Independent of `doh`; enable only this
  feature to use `DotBackend` without pulling in an HTTP client.
- `doh` feature: adds `rustls`, `rustls-pki-types`, `tokio-rustls`, `hyper`,
  `hyper-util`, `hyper-rustls`, `http`, `http-body-util`, `bytes`, and
  `base64` as dependencies. Independent of `dot`; enable only this feature
  to use `DohBackend` without pulling in raw TLS-over-TCP framing you don't
  use directly.
- `doq` feature: adds `rustls`, `rustls-pki-types`, `webpki-roots`, and
  `quinn` as dependencies. Independent of `dot`/`doh`; enable only this
  feature to use `DoqBackend`/`ServerBuilder::doq_addr` without pulling in
  `tokio-rustls`/`hyper`. `quinn`'s `rustls` crypto-provider feature is set
  to `rustls-aws-lc-rs`, matching the workspace `rustls` dependency's own
  `aws-lc-rs` feature (enabled directly on `rustls` itself, not left to
  arrive only transitively via `doh`/`doq` — every TLS handshake needs a
  process-level `CryptoProvider` even with just `dot` enabled on its own).
- `dot`, `doh`, and `doq` all use `rustls` (pure-Rust TLS, no OpenSSL/
  platform-TLS dependency) uniformly on Linux, Windows, and macOS — no
  platform-specific behavior. Cross-platform: no `cfg`-gated logic in any
  backend.
- None of the three features require elevated privileges; all perform
  ordinary outbound TLS/HTTPS/QUIC client connections.

## Usage

```rust
use dns_lattice::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};

let policy = SplitDnsPolicy::builder()
    .rule(
        DomainPattern::suffix(Name::from_ascii("corp.internal").unwrap()),
        UpstreamGroupId::new("corp"),
    )
    .build();

let name = Name::from_ascii("host.corp.internal").unwrap();
assert_eq!(policy.resolve_group(&name), Some(&UpstreamGroupId::new("corp")));
```

## Status

Pre-0.1 stage: this crate has no stable API yet. Stage 0.1 (core model)
landed the DNS message/matcher/policy model above; stage 0.2 landed the
resolver's construct/resolve lifecycle, static split-DNS routing, and its
in-memory TTL/negative-caching answer cache; stage 0.3 is in final
verification and has landed
the public async `upstream` trait, baseline UDP/TCP backends, the opt-in
`dot`/`doh`/`doq` encrypted-transport backends described above, failover
across a group's registered backends, and the `server` module's
embeddable inbound UDP/TCP listener (`Server`/`ServerBuilder`) plus its
opt-in `dot`/`doh`/`doq`-gated inbound DoT/DoH/DoQ listeners
(`ServerBuilder::dot_addr`/`doh_addr`/`doq_addr`). Fake IP and dynamic
routing hooks are not implemented yet (stage 0.4/0.5). Types may change
without notice until the first stable release.
