# DNS Lattice

**Languages**

🇺🇸 **English** | 🇷🇺 [Русский](README.ru.md)

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

**DNS Lattice** is a programmable Rust DNS control plane for the Lattice networking stack — the DNS equivalent of what Kestrel is for HTTP in ASP.NET Core: a full, embeddable DNS server engine that any application hosts to gain split DNS, Fake IP, caching, encrypted upstream transport, and programmable routing, without building a resolver from scratch.

> **Status:** `0.3.0` is published. It delivers the DNS message model, zone/domain
> matcher, split-DNS policy types, resolver/cache, UDP/TCP/DoT/DoH/DoQ
> upstream transports, failover, and matching inbound server listeners
> across three crates — `dns-lattice-core`, `dns-lattice-model`, and the
> `dns-lattice` facade. Development of `0.4` adds the standalone Fake IP
> pool. The API remains pre-1.0; see Current Status below.

## Overview

DNS resolution logic in Rust applications is usually either hand-rolled ad hoc, or pulled in as a heavyweight, fully async, transport-coupled resolver library. DNS Lattice aims to separate the protocol/policy plane (message parsing, zone matching, split-DNS routing, Fake IP) from transport concerns, so applications can embed exactly the DNS server or resolver behavior they need behind one strongly typed API.

## Quick start

The normal inbound path is:

```text
DNS client → Server → Resolver → SplitDnsPolicy → UpstreamBackend → UDP/TCP/DoT/DoH/DoQ
```

Use domain-scoped imports for new code. Flat root aliases remain compatible.

```rust,no_run
use std::{net::SocketAddr, sync::Arc, time::Duration};

use dns_lattice::{
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    server::ServerBuilder,
    upstream::{UdpBackend, UdpBackendConfig},
};

# async fn run() -> dns_lattice::Result<()> {
let group = UpstreamGroupId::new("default");
let policy = SplitDnsPolicy::builder().default_group(group.clone()).build();
let resolver = Arc::new(
    Resolver::builder(policy)
        .backend(
            group,
            UdpBackend::new(UdpBackendConfig {
                server: "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                timeout: Duration::from_secs(5),
                bind_addr: None,
            }),
        )
        .build(),
);
let server = ServerBuilder::new(resolver)
    .udp_addr("127.0.0.1:5353".parse().unwrap())
    .bind()
    .await?;
server.serve().await?;
# Ok(())
# }
```

`Resolver` orchestrates decoded queries, static routing, caching, and
upstream failover. `Server` owns inbound listening and framing;
`UpstreamBackend` implementations own outbound transport execution.

## Workspace crates

The workspace is split into focused crates, mirroring
[net-lattice](https://github.com/F000NKKK/net-lattice)'s topology. Each
crate has its own crate-level README with its scope and a usage example:

| Crate | Purpose |
|---|---|
| [`dns-lattice`](crates/dns-lattice/README.md) | Public facade: re-exports the crates below as the crate's stable surface |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | DNS message, zone/domain matcher, and split-DNS policy model |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Shared `Error`/`Result` types |

## The Lattice ecosystem

DNS Lattice is one crate in a wider Lattice family of composable,
cross-platform Rust networking libraries.

| Crate | Purpose |
|---|---|
| [net-lattice](https://github.com/F000NKKK/net-lattice) | OS networking inspection and configuration (routes, DNS, interfaces) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP tunnel interfaces |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Programmable DNS control plane (this repository) |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Policy compiler: rules -> platform-neutral network plans |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Application-facing SDK composing the crates above |

Cross-repository dependency direction and API boundaries are recorded in
[ARCHITECTURE.md](ARCHITECTURE.md) as that design work happens; `dns-lattice`
has no compile-time dependency on any sibling crate.

## Philosophy

- **Strong typing over raw bytes.** Consumers work with typed messages, names, and records — never manual byte-offset arithmetic.
- **Protocol/policy separate from transport.** The message model, zone matcher, and policy types have no network I/O; transport is layered on top in a later stage behind an explicit backend trait.
- **Deterministic by design.** Zone/domain matching precedence is a documented, tested contract (see [ARCHITECTURE.md](ARCHITECTURE.md)), not incidental iteration order.
- **Typed errors, never panics.** Every fallible operation returns `Result<T, Error>`; malformed wire input is rejected, not undefined behavior.
- **Incremental, well-considered growth.** Each roadmap stage ships a bounded, fully tested slice rather than a large, under-tested surface.

## Capabilities

Implemented (`0.3.0` plus the current `0.4` development slice):

- Hand-rolled DNS message model: header, question, and resource-record encode/decode, including name (de)compression on decode
- Record types: A, AAAA, CNAME, PTR, NS, TXT, MX, SOA, plus a typed fallback for any other record type
- Zone/domain matcher with deterministic exact/suffix/wildcard precedence
- Static split-DNS policy types (`SplitDnsPolicy`) built on the matcher
- In-process, async `Resolver`: construct from a `SplitDnsPolicy`, route one query to an upstream group, and resolve it with failover across that group's registered backends in registration order, with an in-memory TTL-respecting answer cache including RFC 2308 negative caching
- Public, async `upstream` module (`UpstreamBackend` trait, `UdpBackend`, `TcpBackend`): baseline UDP and TCP upstream transports over `tokio`, no EDNS0/OPT yet (UDP falls back to TCP on a truncated response)
- DoT (`DotBackend`, RFC 7858) and DoH (`DohBackend`, RFC 8484) upstream backends, each behind its own default-off `dot`/`doh` Cargo feature, over `rustls`/`tokio-rustls`/`hyper`/`hyper-rustls`
- DoQ (`DoqBackend`, RFC 9250) upstream backend behind its own default-off `doq` Cargo feature, over `quinn` (QUIC transport, TLS 1.3 embedded via `rustls`); a fresh QUIC connection per query in this stage, no connection pooling/reuse yet
- Public, async `server` module (`Server`, `ServerBuilder`): embeddable inbound UDP/TCP DNS listener over an `Arc<Resolver>` — construct/bind/serve/shutdown lifecycle, one task per UDP datagram and one task per TCP connection (looping over multiple length-prefixed queries per RFC 1035 §4.2.2), oversized UDP answers truncated with `TC=1`, and `Rcode::ServFail` synthesis when the resolver returns an error
- Inbound DNS-over-TLS (DoT, RFC 7858) listener behind the `dot` Cargo feature: `ServerBuilder::dot_addr` TLS-accepts each connection via `tokio_rustls::TlsAcceptor` and reuses the same length-prefixed read/write loop as the TCP listener
- Inbound DNS-over-QUIC (DoQ, RFC 9250) listener behind the `doq` Cargo feature: `ServerBuilder::doq_addr` accepts a `quinn` QUIC endpoint (ALPN `doq`) and answers one query per bidirectional stream, reusing the same framing helpers as the `DoqBackend` upstream
- Inbound DNS-over-HTTPS (DoH, RFC 8484) listener behind the `doh` Cargo feature: TCP `ServerBuilder::doh_addr` TLS-accepts each connection via `tokio_rustls::TlsAcceptor`, then serves ALPN-negotiated HTTP/1.1 or HTTP/2 via `hyper_util`'s protocol-detecting server builder over TLS 1.2 or 1.3. A dual-protocol deployment configures `h2` and `http/1.1` ALPN identifiers; GET (`?dns=` base64url) and POST (`application/dns-message` body) work on either protocol.
- HTTP/3 DoH is additive, not a replacement for legacy TCP: `Doh3Backend` and QUIC `ServerBuilder::doh3_addr` use QUIC/UDP with ALPN `h3` and TLS 1.3. Keep TCP `DohBackend`/`doh_addr` for HTTP/1.1 and HTTP/2 clients on TLS 1.2 or 1.3.
- Caller-invoked `fakeip::FakeIpPool`: deterministic, concurrent IPv4 and/or IPv6 allocation and reverse lookup with inclusive ranges and per-family LRU eviction. It is data-only: it does not rewrite DNS answers, synthesize PTR records, apply TTL expiry, persist mappings, or integrate implicitly with `Resolver`, `Server`, TUN/TAP, or `tunnel-lattice`.

Planned (see [ROADMAP.md](ROADMAP.md)):

- Dynamic routing hooks for caller-driven policy (stage 0.5)
- Cross-platform CI matrix, fuzz/property tests, observability sink (stage 0.6)

## Transport features

UDP and TCP are available in the default build. Encrypted transports are
opt-in and independent: enable `dot` for DoT, `doh` for DoH (including
HTTP/3 support), and `doq` for DoQ. They are default-off so applications
that only need UDP/TCP do not inherit TLS, HTTP, or QUIC dependencies.

## Non-Goals

- DNS Lattice does not own OS-level DNS configuration mutation — that is [net-lattice](https://github.com/F000NKKK/net-lattice)'s responsibility.
- DNS Lattice does not compile a rule syntax — that is [flow-lattice](https://github.com/F000NKKK/flow-lattice)'s responsibility.
- DNS Lattice does not manage TUN/TAP devices — that is [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice)'s responsibility.
- DNS Lattice does not ship as a standalone server product (CLI, config file format, process supervision) — only the embeddable serving *engine* is in scope; packaging it as an installable daemon belongs to an application built on top, typically via [sdk-lattice](https://github.com/F000NKKK/sdk-lattice).

## Current Status

Stages 0.1-0.2 plus the implementation scope of stage 0.3 of the
[architecture](ARCHITECTURE.md)'s module layout is covered by
deterministic unit/doc tests, `clippy -D warnings`, and verified `cargo
package` listings for all three crates:

- `dns-lattice-core`'s `Error`/`Result` pair, hand-rolled `Display`/`std::error::Error`
- `dns-lattice-model`'s `message` (`Message`, `Header`, `Question`, `ResourceRecord`), `record` (`RecordType`, `Class`, `RData`), `matcher` (`DomainPattern`, `DomainMatcher<T>`), and `policy` (`SplitDnsPolicy`) modules
- the `dns-lattice` facade's `engine` module (`Resolver`, `ResolverBuilder`): in-process, async construct/resolve, static split-DNS routing, failover across a matched group's registered backends in registration order, and an in-memory TTL-respecting/negative-caching answer cache
- the `dns-lattice` facade's `upstream` module (`UpstreamBackend`, `UdpBackend`, `TcpBackend`): baseline UDP/TCP upstream transports over `tokio`, no EDNS0/OPT yet
- the `dns-lattice` facade's `upstream` module's opt-in `dot`/`doh` Cargo features (`DotBackend`, `DohBackend`): DNS-over-TLS/DNS-over-HTTPS transports over `rustls`/`hyper`, tested against loopback TLS/HTTPS fixtures with a locally generated self-signed certificate
- the `dns-lattice` facade's `upstream` module's opt-in `doq` Cargo feature (`DoqBackend`): DNS-over-QUIC transport over `quinn`/`rustls`, tested against a loopback `quinn` QUIC server fixture with a locally generated self-signed certificate
- the `dns-lattice` facade's `server` module (`Server`, `ServerBuilder`): inbound UDP/TCP listener over an in-process fake `Resolver` fixture, covering round-trip resolution over both transports, UDP truncation/`TC=1` behavior, `Rcode::ServFail` synthesis on a resolver error, and graceful shutdown via `serve_until`
- the `dns-lattice` facade's `server` module's opt-in `dot` Cargo feature (`ServerBuilder::dot_addr`): inbound DNS-over-TLS listener, tested against a loopback TLS client with a locally generated self-signed certificate, covering round-trip resolution, multiple queries over one TLS connection, and `Rcode::ServFail` synthesis on a resolver error
- the `dns-lattice` facade's `server` module's opt-in `doq` Cargo feature (`ServerBuilder::doq_addr`): inbound DNS-over-QUIC listener, tested against a loopback `quinn` QUIC client with a locally generated self-signed certificate, covering round-trip resolution, multiple queries over one QUIC connection (separate streams), and `Rcode::ServFail` synthesis on a resolver error
- the `dns-lattice` facade's `server` module's opt-in `doh` Cargo feature: TCP `ServerBuilder::doh_addr`, tested end-to-end over ALPN-negotiated HTTP/1.1 and HTTP/2 with a locally generated self-signed certificate, and QUIC `ServerBuilder::doh3_addr`, tested over HTTP/3 with ALPN `h3`; both cover GET and POST round trips, with HTTP/3 also covering 400/404 and DNS `SERVFAIL` response semantics

This gives a complete, tested DNS message model, a deterministic
zone/domain matcher, an in-process resolver with real UDP/TCP/DoT/DoH/DoQ
upstream transport and failover across a group's backends, and an
embeddable inbound UDP/TCP/DoT/DoH/DoQ DNS server listener, all usable
standalone today. The current development state also provides the standalone,
caller-invoked Fake IP pool described above; it is not part of the resolver
or server query path yet.

| Capability | Status |
|---|:---:|
| DNS message encode/decode | ✅ |
| Name (de)compression on decode | ✅ |
| Zone/domain matcher (exact/suffix/wildcard) | ✅ |
| Static split-DNS policy types | ✅ |
| Resolver engine / answer cache | ✅ |
| UDP/TCP upstream backends | ✅ |
| DoT/DoH upstream backends (`dot`/`doh` Cargo features) | ✅ |
| DoQ upstream backend (`doq` Cargo feature) | ✅ |
| Upstream failover across a group's backends | ✅ |
| Inbound UDP/TCP server listener | ✅ |
| Inbound DoT server listener (`dot` Cargo feature) | ✅ |
| Inbound DoQ server listener (`doq` Cargo feature) | ✅ |
| Inbound DoH server listener (`doh` Cargo feature) | ✅ |
| Fake IP pool (caller-invoked, data-only) | ✅ (0.4 development) |
| Dynamic routing hooks | planned (0.5) |

## Examples

The runnable sources in
[`crates/dns-lattice/examples`](crates/dns-lattice/examples) cover the
model surface available today:

| Scenario | Runnable example | API covered |
|---|---|---|
| Split-DNS policy resolution | [`split_dns_policy`](crates/dns-lattice/examples/split_dns_policy.rs) | `SplitDnsPolicy`, `DomainPattern`, exact/suffix/wildcard precedence, default group fallback |
| Message wire round-trip | [`message_round_trip`](crates/dns-lattice/examples/message_round_trip.rs) | `Message::encode`, `Message::decode`, `Header`, `Question`, `ResourceRecord`, `RData::A` |
| Resolver with split-DNS + cache | [`resolver`](crates/dns-lattice/examples/resolver.rs) | `Resolver`, `ResolverBuilder`, in-process fake upstream backends, TTL answer cache, `Error::NoRoute` |

Run an example with `cargo run -p dns-lattice --example <name>`.

## Roadmap

1. **Stage 0.0: Audit, roadmap, architecture baseline** *(completed)* — repository audit, target module layout, and non-goals.
2. **Stage 0.1: Core model** *(completed)* — DNS message model, zone/domain matcher, split-DNS policy types, `dns-lattice-core`/`dns-lattice-model`/`dns-lattice` crate split.
3. **Stage 0.2: Resolver engine and static split DNS** *(completed)* — construct-resolve-shutdown resolver entry point, static split-DNS routing, in-memory answer cache with negative caching, fake in-process upstream for deterministic tests.
4. **Stage 0.3: Upstream transport backends and server listener** *(completed)* — stabilized upstream backend trait, UDP/TCP baseline, DoT/DoH/DoQ behind `dot`/`doh`/`doq` Cargo features, fallback/failover across upstreams within a group, and an embeddable inbound UDP/TCP/DoT/DoH/DoQ server listener (`Server`/`ServerBuilder`).
5. **Stage 0.4: Fake IP pool** *(active)* — caller-invoked deterministic synthetic address allocation, reverse lookup, and LRU eviction; no implicit DNS rewrite, TTL expiry, persistence, or tunnel integration.
6. **Stage 0.5: Dynamic routing hooks** — stable hook trait(s) for caller-driven routing, composition/precedence against static rules.
7. **Stage 0.6: Hardening and platform validation** — cross-platform CI matrix, fuzz/property tests, observability sink, full documentation sync.
8. **Stage 1.0: Stable public API and first release** — public API frozen, `cargo package`/docs.rs verified, first crates.io release.

Stages are delivery boundaries, not a promise of one release per heading;
see [ROADMAP.md](ROADMAP.md) for the full non-goal list per stage.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community
expectations, and [SECURITY.md](SECURITY.md) for reporting security issues.
Feedback on scope, API design, and architecture is the most valuable
contribution at this stage.

## License

Licensed under the [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).
