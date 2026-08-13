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
  listener. DoT/DoH/DoQ inbound listeners are still planned.

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
  feature to use `DoqBackend` without pulling in `tokio-rustls`/`hyper`.
  `quinn`'s `rustls` crypto-provider feature is set to `rustls-aws-lc-rs`,
  sharing the same `aws-lc-rs` provider `doh`'s `hyper-rustls` dependency
  already pulls in, rather than compiling in a second (`ring`-based)
  provider.
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
in-memory TTL/negative-caching answer cache; stage 0.3 (in progress) has so
far landed the public async `upstream` trait, baseline UDP/TCP backends,
the opt-in `dot`/`doh`/`doq` encrypted-transport backends described above,
failover across a group's registered backends, and the `server` module's
embeddable inbound UDP/TCP listener (`Server`/`ServerBuilder`). The inbound
DoT/DoH/DoQ server listeners, Fake IP, and dynamic routing hooks are not
implemented yet. Types may change without notice until the first stable
release.
