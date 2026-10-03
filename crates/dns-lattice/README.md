<div align="center">

# 🧭 dns-lattice

### A Programmable, Embeddable DNS Resolver and Server Engine for Rust

[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice?cacheSeconds=86400)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![CI](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/dns-lattice)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

[Overview](#-overview) • [Installation](#-installation) • [Quick Start](#-quick-start)
• [How It Works](#-how-it-works) • [Transports](#-transports)
• [Safety](#-safety-and-responsibility)

</div>

---

## 📖 Overview

The application-facing crate of [DNS Lattice](https://github.com/F000NKKK/dns-lattice): an
embeddable DNS resolver and server engine with split DNS, a TTL-aware, byte-bounded cache scoped by
upstream group, Fake IP, dynamic route selection, structured observability, and UDP/TCP/DoT/DoH/DoQ
transports in both directions. It is for Rust applications that need custom DNS behavior: the
host application owns the process and configuration, while this crate owns DNS protocol
handling, resolution, serving, routing, cache behavior, and transport execution. It is a
library, not a standalone CLI, config-file, or service product.

It re-exports the model and shared error crates through canonical `dns_lattice::*` domain
modules; flat root aliases are intentionally not exposed:

- `core`: shared `Error` / `Result`;
- `model`: DNS messages, records, names, domain matcher, split-DNS policy, upstream-group IDs;
- `engine`: `Resolver` / `ResolverBuilder` (routing, cache, ordered failover);
- `cache`: `CacheConfig` for the answer cache (memory bound, shard count, TTL limits), passed
  to `ResolverBuilder::cache`;
- `upstream`: the `UpstreamBackend` trait (implement it for your own transport) and the
  built-in UDP, TCP, DoT, DoH, DoH3, and DoQ backends;
- `server`: `Server` / `ServerBuilder`, inbound listeners on the same transports over a shared
  `Arc<Resolver>`, with `serve` and `serve_until`;
- `fakeip`: `FakeIpPool` / `FakeIpPolicy`; `hooks`: the `RouteHook` dynamic route-selection
  hook; `observability`: the `ObservabilitySink` event sink.

## 📦 Installation

```toml
[dependencies]
dns-lattice = "1.1"
tokio = { version = "1.53.1", features = ["rt-multi-thread", "macros"] }

# Encrypted transports are opt-in:
# dns-lattice = { version = "1.1", features = ["dot", "doh", "doq"] }
```

Features are independent and default-off; without any of them the crate builds UDP and TCP,
client and server, on `tokio` alone. MSRV: Rust 1.93.

- `dot`: DNS-over-TLS (`rustls`, `tokio-rustls`, `webpki-roots`);
- `doh`: DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3 (`hyper`, `hyper-rustls`, `h3`,
  `quinn`);
- `doq`: DNS-over-QUIC, without the HTTP stack (`quinn`, `rustls`, `webpki-roots`).

## 🎓 Quick Start

```rust,no_run
use std::{net::SocketAddr, sync::Arc, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    server::ServerBuilder,
    upstream::{UdpBackend, UdpBackendConfig},
};

async fn run() -> Result<()> {
    let group = UpstreamGroupId::new("default");
    let policy = SplitDnsPolicy::builder()
        .default_group(group.clone())
        .build();

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
    Ok(())
}
```

`Resolver` owns routing, cache, and failover; `Server` owns inbound listening and protocol
framing; `UpstreamBackend` implementations own outbound transport. Split DNS with failover,
DoT, Fake IP, route hooks, observability, and graceful shutdown are shown in the
[repository examples](https://github.com/F000NKKK/dns-lattice#-examples).

## 🔄 How It Works

**Pipeline.** For an ordinary query the resolver takes the static split-DNS candidate
(deterministic exact/suffix/wildcard precedence), lets the optional route hook replace it,
validates the effective upstream group, consults the cache scoped to that group, then tries
the group's backends in order. Fake IP is a terminal path before routing, cache, and
upstreams when its policy selects the query.

**Cache.** Answers are cached in memory by DNS TTL, with negative caching. Ordinary cache
identity includes the effective upstream group and the query's RD and EDNS DO bits, so equal
questions routed to different groups never share an answer. Answers are stored without their OPT
record; an answer to an EDNS(0) query always carries one, and an answer to a plain query never
does. The cache is sharded and bounded to about 16 MiB by default (an estimate of heap use),
enforced on every insert by evicting expired entries first and then entries that were never
reused, so a flood of one-off names cannot grow it or push out the popular names. Use
`ResolverBuilder::cache(CacheConfig::new().max_bytes(..))` to change the bound, the shard count,
or the TTL limits (positive 0 s to 86 400 s, negative 0 s to 3 600 s by default), or
`CacheConfig::disabled()` to keep nothing.

**Route hook.** `ResolverBuilder::route_hook` takes one `RouteHook`, which receives the first
question and the tentative static group and returns `RouteDecision::Use(group)` (a
registered, nonempty group) or `Abstain` (keep the static candidate). A hook error, unknown
group, or empty group is a resolver error with no cache or upstream fallback. Hooks are
selection-only: they receive no resolver or backend handles, client transport metadata, or
OS/network side-effect authority. Hook implementations own timeout, retry, cancellation
cleanup, and external integration, and must not re-enter the same resolver.

**Fake IP.** `FakeIpPool` allocates synthetic addresses from optional inclusive IPv4/IPv6
ranges, safe for concurrent use, with deterministic domain-to-address allocation and reuse,
reverse lookup of active mappings, per-family LRU eviction when a range is full, a required
whole-second TTL and expiry, and caller-owned, process-local, in-memory snapshot/restore.
With `ResolverBuilder::fake_ip`, matching IN A/AAAA queries get a local synthetic answer, a
selected but disabled family gets NODATA, and a canonical PTR inside a configured range gets
the active mapping or NXDOMAIN. These answers bypass the answer cache and upstreams, and
their TTL never exceeds the mapping's remaining lifetime. The crate does not serialize
snapshots or persist Fake IP state durably.

**Observability.** An optional synchronous `ObservabilitySink` receives immutable, bounded
events for query receipt, Fake IP, route and hook decisions, cache hit/miss, upstream
attempts and outcomes, timeouts, and terminal failures. Callbacks cannot change routing,
cache state, retries, or answers, receive no resolver or backend handles, run after resolver
locks are released, and have their panics isolated from resolver correctness. The crate
requires no logging or tracing framework and owns no background telemetry queue.

Details: [ARCHITECTURE.md](https://github.com/F000NKKK/dns-lattice/blob/main/ARCHITECTURE.md#resolver-data-flow)
and [docs.rs](https://docs.rs/dns-lattice).

## 🔐 Transports

Upstream backends are async. A group's backends are tried in registration order; timeout,
transport, and TLS failures can fall over to the next one, and if all fail the last error is
returned. Each built-in backend checks that a response answers its query before returning
it: `QR` must be set and the question must match; the message id must match too, except on
DoH and DoQ, where a server may answer with id 0 (the response is returned with the
caller's id).

- **UDP** (default): `UdpBackend` / `udp_addr`; falls back to TCP when a response has `TC=1`.
- **TCP** (default): `TcpBackend` / `tcp_addr`, RFC 1035 framing.
- **DoT** (`dot`): `DotBackend` / `dot_addr`, over `rustls`/`tokio-rustls`.
- **DoH** HTTP/1.1 + HTTP/2 (`doh`): `DohBackend` / `doh_addr`, over `hyper`/`hyper-rustls`.
- **DoH3** HTTP/3 (`doh`): `Doh3Backend` / `doh3_addr`, over `h3`/`quinn`, ALPN `h3`, TLS 1.3.
- **DoQ** (`doq`): `DoqBackend` / `doq_addr`, over `quinn`, ALPN `doq`, TLS 1.3.

Names are given as backend type / `ServerBuilder` listener method. Every upstream query
currently opens a fresh socket or connection. The host provides TLS/QUIC server configuration
and certificate material for the listeners. The inbound UDP listener answers an EDNS(0) client
with up to min(its advertised payload size, 1232 bytes) — `ServerBuilder::edns_udp_payload_size`
changes the maximum, never below 512 — and a plain client with up to 512 bytes; larger answers
are truncated (`TC=1`) for a TCP retry. Malformed OPT records get a local `FORMERR` that carries a
bare server OPT record (RFC 6891 §7), and EDNS versions above 0 a local `BADVERS`. Contract details:
[upstream](https://github.com/F000NKKK/dns-lattice/blob/main/ARCHITECTURE.md#upstream-transport-contract)
and [server](https://github.com/F000NKKK/dns-lattice/blob/main/ARCHITECTURE.md#inbound-server-contract).

## 💻 Platforms

Linux, Windows, and macOS. CI on each runs the workspace format, lint, check, test, and doc
gates, plus strict per-feature check, test, and rustdoc for `--no-default-features`, `dot`,
`doh`, `doq`, and `--all-features`. Tests use local loopback servers; CI does not contact
public resolvers. CI also lists package contents and runs a hermetic release-automation
regression; validation does not publish crates. Every built-in backend and listener does its
I/O through Tokio, so call them inside a Tokio runtime. See the
[platform matrix](https://github.com/F000NKKK/dns-lattice#-supported-transports-and-platforms)
and [troubleshooting](https://github.com/F000NKKK/dns-lattice#-troubleshooting).

## 🔒 Safety and Responsibility

This crate performs ordinary socket, TLS, and QUIC networking. It does not mutate OS DNS
configuration or manage TUN/TAP devices; those belong to the host application or sibling
Lattice components. Binding privileged ports, configuring the OS resolver, and provisioning
certificates are host responsibilities. Route hooks and observability sinks do not receive
privileged runtime handles from DNS Lattice; an application that intentionally performs side
effects from its own hook or sink implementation is responsible for those effects.

## 📌 Status

**Stable `1.x` releases are published** on crates.io. Stages 0.0 through 1.0 are complete,
and ordinary SemVer applies within `1.x`: additive changes are minor releases, fixes are
patch releases, and a breaking change requires an explicit major version bump.

**Documentation:** [API reference](https://docs.rs/dns-lattice) •
[project](https://github.com/F000NKKK/dns-lattice) •
[architecture](https://github.com/F000NKKK/dns-lattice/blob/main/ARCHITECTURE.md) •
[changelog](https://github.com/F000NKKK/dns-lattice/blob/main/CHANGELOG.md)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE).
