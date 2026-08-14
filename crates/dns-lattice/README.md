# dns-lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## What it provides

For new code, prefer the canonical domain modules:

- `dns_lattice::model` — DNS messages, names, matcher, and split-DNS policy;
- `dns_lattice::engine` — `Resolver` query orchestration, cache, and
  upstream failover;
- `dns_lattice::upstream` — the outbound backend trait and transports;
- `dns_lattice::server` — inbound listener construction and lifecycle;
- `dns_lattice::fakeip` — synthetic-address pool, policy, and snapshots;
- `dns_lattice::hooks` — caller-supplied dynamic upstream-group selection;
- `dns_lattice::core` — shared `Error` and `Result` types.

The facade deliberately exposes no flat root aliases.

- `dns-lattice-model`'s DNS message model (`Message`, `Header`, `Question`,
  `ResourceRecord`, `RData`), zone/domain matcher (`DomainPattern`,
  `DomainMatcher`), and split-DNS policy types (`SplitDnsPolicy`), re-exported
  through this facade crate.
- `dns-lattice-core`'s `Error`/`Result` pair.
- A synchronous, concurrent `fakeip` module (`FakeIpPool`,
  `FakeIpPoolBuilder`): configure one or both inclusive synthetic IPv4/IPv6
  ranges, allocate or reuse one address per DNS name, and reverse-resolve an
  address to its currently assigned name. Allocation uses a family-salted
  deterministic hash and circular probing; a full family evicts its LRU
  mapping. Mappings have a required whole-second TTL and caller-owned,
  process-local in-memory snapshots can restore their live entries and LRU
  order. The pool itself performs no socket I/O or durable persistence.
- An in-process resolver entry point (`Resolver`, `ResolverBuilder`): route
  one query through a `SplitDnsPolicy` to an upstream group, then try that
  group's registered backends in registration order — a backend failing
  with a timeout/transport/TLS error falls over to the next backend in the
  group, and the first success is cached in memory (TTL-respecting, with
  RFC 2308 negative caching) so a repeated query is served without
  re-querying the backend. Once every backend in the group has failed, the
  last attempted backend's error is returned as-is. `ResolverBuilder::fake_ip`
  explicitly adds local Fake IP behavior: matching IN A/AAAA questions
  allocate or reuse a synthetic address, while canonical IN PTR questions in
  the configured ranges return a live mapping or NXDOMAIN. A selected but
  disabled A/AAAA family returns local NODATA. These answers bypass the
  ordinary cache and upstreams and use the mapping's remaining lifetime as
  their DNS TTL. `Resolver::resolve` is `async fn` and must be called from
  inside a `tokio` runtime.
- A public, async `upstream` module (`UpstreamBackend` trait, `UdpBackend`,
  `TcpBackend`): baseline UDP and TCP upstream transports, no EDNS0/OPT
  support yet (`UdpBackend` falls back to a TCP query when a response's
  `TC` bit is set).
- Three opt-in, default-off Cargo features adding encrypted upstream
  transports to the same `upstream` module: `dot` (`DotBackend`/
  `DotBackendConfig`, DNS-over-TLS, RFC 7858, over `rustls`/`tokio-rustls`),
  `doh` (`DohBackend`/`DohBackendConfig`/`DohMethod`, DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats, over `hyper`/`hyper-rustls`, plus
  `Doh3Backend`/`Doh3BackendConfig` for HTTP/3 over QUIC), and
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
  it TLS-accepts each TCP connection like `dot_addr` over TLS 1.2 or 1.3,
  then serves the ALPN-negotiated HTTP/1.1 or HTTP/2 protocol via `hyper_util`'s
  protocol-detecting server builder, parsing RFC 8484 GET (`?dns=`
  base64url query parameter) and POST (`application/dns-message` body)
  requests. A dual-protocol deployment configures `h2` and `http/1.1` in
  its `rustls::ServerConfig` ALPN list. `config` (a `DohListenerConfig`, defaulting to the
  `/dns-query` path) selects which URI path the listener answers; any
  other path gets HTTP 404, an unsupported method or undecodable request
  gets HTTP 400, and everything else is answered HTTP 200 with an
  `application/dns-message` body — including a synthesized `Rcode::ServFail`
  on a resolver error, matching every other transport's error policy.
  `ServerBuilder::doh3_addr(addr, quinn_config, config)` separately binds
  HTTP/3 over QUIC/UDP with ALPN `h3` and TLS 1.3. Keep `doh_addr` for
  HTTP/1.1/HTTP/2 legacy TCP clients on TLS 1.2 or 1.3.

For ordinary queries, `ResolverBuilder::route_hook` accepts one caller-owned
`hooks::RouteHook`. The resolver supplies the first question and the tentative
static group; `Use(group)` selects a registered, nonempty group, while
`Abstain` keeps static routing. Fake IP local answers are terminal before the
hook. The effective group scopes the answer cache, so answers cannot cross
between different hook-selected groups. A hook error, an unknown group, or an
empty group returns a resolver error without cache or upstream fallback.
Hooks own timeout, retry, and cancellation cleanup, and must not re-enter the
same resolver. They are selection-only: they receive neither resolver/backend
handles nor client metadata or side-effect capabilities.

## Dynamic route hook

For an ordinary query, the resolver obtains the static split-DNS candidate,
calls at most one hook, validates the effective group, checks that group's
cache scope, and only then executes ordered upstream failover. Local Fake IP
answers are terminal before this path. This example is entirely in-process and
opens no socket. Applications implementing `RouteHook` should add
`async-trait` to their dependencies.

```rust,no_run
use async_trait::async_trait;
use dns_lattice::{
    core::Result,
    engine::Resolver,
    hooks::{RouteDecision, RouteHook, RouteHookError, RouteRequest},
    model::{Message, SplitDnsPolicy, UpstreamGroupId},
    upstream::UpstreamBackend,
};

struct PreferFiltered;

#[async_trait]
impl RouteHook for PreferFiltered {
    async fn select(
        &self,
        request: RouteRequest<'_>,
    ) -> std::result::Result<RouteDecision, RouteHookError> {
        let _question = request.question();
        let _static_candidate = request.static_group();
        Ok(RouteDecision::Use(UpstreamGroupId::new("filtered")))
    }
}

struct InProcessBackend;

#[async_trait]
impl UpstreamBackend for InProcessBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        Ok(query.clone())
    }
}

let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
    .backend(UpstreamGroupId::new("filtered"), InProcessBackend)
    .route_hook(PreferFiltered)
    .build();
# let _ = resolver;
```

`Use` must choose a registered, nonempty group; `Abstain` preserves the static
candidate. A hook error, unknown group, or empty group returns a resolver error
without static fallback, cache access, or an upstream call. Cache entries are
scoped by the validated effective group, so equal questions routed differently
cannot share an answer. Dropping `Resolver::resolve` drops the in-flight hook
future; hook implementations own timeout, retry, and cancellation cleanup and
must not re-enter the same resolver. Hooks receive no resolver/backend handle,
client metadata, or OS/network side-effect capability. Compose side effects in
the host application or another external layer.

## Observability

`ResolverBuilder::observability_sink` accepts an optional synchronous
`observability::ObservabilitySink`. The sink receives immutable bounded events
for query receipt, terminal Fake IP handling, route-hook decisions, cache
hits/misses, upstream attempts/outcomes, timeouts, and terminal errors. It is
non-authoritative: callback panics are isolated and events cannot change
routing, answers, retries, or cache state. DNS Lattice invokes callbacks after
releasing resolver locks and does not create a background queue or integrate
with logging, OS networking, tunnel-lattice, flow-lattice, or sdk-lattice.

## Feature/platform constraints

- Default build: no Cargo features enabled. Carries no TLS/HTTP dependency
  weight — only `dns-lattice-core`, `dns-lattice-model`, `async-trait`, and
  `tokio` (with `net`/`time`/`rt`/`macros`/`io-util` only).
- `dot` feature: adds `rustls`, `rustls-pki-types`, `tokio-rustls`, and
  `webpki-roots` as dependencies. Independent of `doh`; enable only this
  feature to use `DotBackend` without pulling in an HTTP client.
- `doh` feature: adds `rustls`, `rustls-pki-types`, `tokio-rustls`, `hyper`,
  `hyper-util`, `hyper-rustls`, `http`, `http-body-util`, `bytes`, `base64`,
  `h3`, `h3-quinn`, and `quinn` as dependencies. It deliberately includes
  both TCP DoH and HTTP/3-over-QUIC (`Doh3Backend`/
  `ServerBuilder::doh3_addr`). Independent of `dot`; enable only this feature
  to use DoH without raw TLS-over-TCP framing you do not use directly.
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
use dns_lattice::model::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};

let policy = SplitDnsPolicy::builder()
    .rule(
        DomainPattern::suffix(Name::from_ascii("corp.internal").unwrap()),
        UpstreamGroupId::new("corp"),
    )
    .build();

let name = Name::from_ascii("host.corp.internal").unwrap();
assert_eq!(policy.resolve_group(&name), Some(&UpstreamGroupId::new("corp")));
```

```rust
use std::{net::Ipv4Addr, time::Duration};

use dns_lattice::{core::Error, fakeip::FakeIpPool, model::Name};

let pool = FakeIpPool::builder()
    .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 254))
    .ttl(Duration::from_secs(60))
    .build()?;
let address = pool.allocate_ipv4(Name::from_ascii("service.internal")?)?;
assert_eq!(pool.lookup_ipv4(address), Some(Name::from_ascii("service.internal")?));

let snapshot = pool.snapshot();
let restored = FakeIpPool::restore(snapshot)?;
assert_eq!(restored.lookup_ipv4(address), Some(Name::from_ascii("service.internal")?));
# Ok::<(), Error>(())
```

```rust
use std::sync::Arc;

use dns_lattice::{
    engine::Resolver,
    fakeip::{FakeIpPolicy, FakeIpPool},
    model::{DomainPattern, Name, SplitDnsPolicy},
};

# let pool = Arc::new(FakeIpPool::builder()
#     .ipv4_range("198.18.0.1".parse()?, "198.18.0.254".parse()?)
#     .ttl(std::time::Duration::from_secs(60))
#     .build()?);
let fake_ip_policy = FakeIpPolicy::builder()
    .rule(DomainPattern::suffix(Name::from_ascii("internal")?))
    .build();
let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
    .fake_ip(pool, fake_ip_policy)
    .build();
# let _ = resolver;
# Ok::<(), dns_lattice::core::Error>(())
```

## Status

Version `0.5.0` is published and this crate remains pre-1.0: its public API
may change before the first stable release. Stage 0.1 (core model)
landed the DNS message/matcher/policy model above; stage 0.2 landed the
resolver's construct/resolve lifecycle, static split-DNS routing, and its
in-memory TTL/negative-caching answer cache; stage 0.3 landed
the public async `upstream` trait, baseline UDP/TCP backends, the opt-in
`dot`/`doh`/`doq` encrypted-transport backends described above, failover
across a group's registered backends, and the `server` module's
embeddable inbound UDP/TCP listener (`Server`/`ServerBuilder`) plus its
opt-in `dot`/`doh`/`doq`-gated inbound DoT/DoH/DoQ listeners
(`ServerBuilder::dot_addr`/`doh_addr`/`doq_addr`). Published Stage 0.4 adds
the opt-in Fake IP resolver behavior above, TTL expiry, and caller-owned
process-local snapshot/restore; it does not add durable persistence. Dynamic
Dynamic routing hooks are included in the published `0.5.0` release. Stage 0.6
hardening is active on `main`. Types may change without notice until the first stable
release.
