# dns-lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## What it provides

- `dns-lattice-model`'s DNS message model (`Message`, `Header`, `Question`,
  `ResourceRecord`, `RData`), zone/domain matcher (`DomainPattern`,
  `DomainMatcher`), and split-DNS policy types (`SplitDnsPolicy`), re-exported
  through this facade crate.
- `dns-lattice-core`'s `Error`/`Result` pair.
- An in-process resolver entry point (`Resolver`, `ResolverBuilder`): route
  one query through a `SplitDnsPolicy` to an upstream group, forward it to
  that group's first registered backend, and cache the answer in memory
  (TTL-respecting, with RFC 2308 negative caching) so a repeated query is
  served without re-querying the backend. `Resolver::resolve` is `async fn`
  and must be called from inside a `tokio` runtime.
- A public, async `upstream` module (`UpstreamBackend` trait, `UdpBackend`,
  `TcpBackend`): baseline UDP and TCP upstream transports, no EDNS0/OPT
  support yet (`UdpBackend` falls back to a TCP query when a response's
  `TC` bit is set). Failover across upstreams within a group and the
  inbound server listener are still planned.
- Two opt-in, default-off Cargo features adding encrypted upstream
  transports to the same `upstream` module: `dot` (`DotBackend`/
  `DotBackendConfig`, DNS-over-TLS, RFC 7858, over `rustls`/`tokio-rustls`)
  and `doh` (`DohBackend`/`DohBackendConfig`/`DohMethod`, DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats, over `hyper`/`hyper-rustls`). A DoQ
  backend is still planned.

Server, Fake IP, and dynamic routing hook capabilities are planned for
later stages; see `ROADMAP.md` in the repository root.

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
- Both `dot` and `doh` use `rustls` (pure-Rust TLS, no OpenSSL/platform-TLS
  dependency) uniformly on Linux, Windows, and macOS — no platform-specific
  behavior. Cross-platform: no `cfg`-gated logic in either backend.
- Neither feature requires elevated privileges; both perform ordinary
  outbound TLS/HTTPS client connections.

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
and the opt-in `dot`/`doh` encrypted-transport backends described above. A
DoQ backend, upstream failover, the inbound server listener, Fake IP, and
dynamic routing hooks are not implemented yet. Types may change without
notice until the first stable release.
