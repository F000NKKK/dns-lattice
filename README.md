<div align="center">

<a id="top"></a>

# 🧭 DNS Lattice

### A Programmable, Embeddable DNS Resolver and Server Engine for Rust

[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice?cacheSeconds=86400)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice)
[![CI](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

🇺🇸 **English** | 🇷🇺 [Русский](README.ru.md)

[Features](#-key-features) • [Transports](#-supported-transports-and-platforms) • [Performance](#-performance) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Comparison](#-comparison)

</div>

---

## 📖 Overview

**DNS Lattice** is a programmable, embeddable DNS resolver/server engine for
Rust. It provides split DNS, caching, Fake IP, dynamic route selection,
structured observability, and UDP/TCP/DoT/DoH/DoQ transports behind one typed
library API.

Think of it as the DNS equivalent of an embeddable HTTP server core: the host
application owns the process and configuration, while DNS Lattice owns DNS
protocol handling, resolution, serving, routing, cache behavior, and transport
execution.

Applications that need custom DNS behavior often end up combining several
concerns manually: DNS wire parsing, split-DNS policy, cache semantics,
transport fallback, encrypted DNS, Fake IP state, server listeners, and
application-specific routing. DNS Lattice keeps those concerns separate but
composable.

### 🎯 Why DNS Lattice?

- **🔀 Split DNS is the core, not an add-on**: every query is routed to a
  named upstream group by deterministic exact/suffix/wildcard rules before
  anything else happens.
- **🧊 A cache that respects routes**: cache entries are keyed by the
  effective upstream group, so the same question sent to two routes never
  shares an answer.
- **🎭 Fake IP built in**: a concurrent IPv4/IPv6 synthetic-address pool with
  reverse lookup, LRU eviction, TTLs, and snapshots, wired into the resolver
  as a terminal answer path.
- **🪝 Dynamic routing without giving away control**: a `RouteHook` picks the
  upstream group per question, but gets no resolver, backend, cache, or OS
  handle.
- **🔐 Every transport, both directions**: UDP, TCP, DoT, DoH (HTTP/1.1,
  HTTP/2, HTTP/3), and DoQ as upstream clients *and* inbound listeners, with
  the encrypted ones behind opt-in Cargo features.
- **📡 Observability without a framework**: bounded, immutable resolver
  events delivered to your own sink; no logging or tracing crate required.
- **🧾 A stable API**: `1.x` follows SemVer; a breaking change needs a new
  major version.

> **Status:** **stable `1.x` releases are published** on crates.io
> (`dns-lattice`, `dns-lattice-core`, `dns-lattice-model`). Stages 0.0
> through 1.0 are complete: the public API is frozen and the workspace
> follows ordinary SemVer within the `1.x` line — a breaking change requires
> an explicit major version bump. See [CHANGELOG.md](CHANGELOG.md) for the
> current version.

## 🌟 Key Features

### Resolution
- ✅ **Static split DNS**: `SplitDnsPolicy` maps exact, suffix, and wildcard
  domain patterns to upstream groups, with an optional default group
- ✅ **TTL and negative cache**: in-memory answers expire with their DNS TTL;
  NXDOMAIN and empty answers are cached too
- ✅ **Bounded, sharded cache**: memory is capped (16 MiB by default, an
  estimate) and enforced on every insert; `CacheConfig` sets the cap, the
  shard count, and the TTL limits
- ✅ **Ordered failover**: backends in one group are tried in registration
  order; timeout, transport, and TLS failures move on to the next one
- ✅ **Fake IP synthesis**: matching A/AAAA and in-range PTR questions are
  answered locally from a `FakeIpPool`

### Transports
- ✅ **UDP and TCP** in the default build, with UDP → TCP fallback on `TC=1`
- ✅ **DoT** (`dot`), **DoH** over HTTP/1.1, HTTP/2, and HTTP/3 (`doh`), and
  **DoQ** (`doq`), each an independent, default-off Cargo feature
- ✅ **Inbound server** on the same transports, sharing one `Arc<Resolver>`

### Extensibility
- 🪝 **`RouteHook`**: async, selection-only upstream-group choice per question
- 📡 **`ObservabilitySink`**: synchronous, non-authoritative resolver events
- 🔌 **`UpstreamBackend`**: implement your own transport and register it next
  to the built-in ones

### Developer Experience
- 🧭 **One typed `Error`** for message, policy, transport, TLS, hook, and
  Fake IP failures
- 🗂️ **Domain-scoped modules** (`engine`, `upstream`, `server`, `fakeip`,
  ...) instead of a flat root namespace
- 🧪 **Loopback-tested transports**: every client and listener is exercised
  against a local server on Linux, Windows, and macOS in CI

## 💻 Supported Transports and Platforms

| Transport | Feature | Upstream client | Inbound server | Linux | Windows | macOS |
|-----------|---------|:---------------:|:--------------:|:-----:|:-------:|:-----:|
| **UDP** | default | ✅ `UdpBackend` | ✅ `udp_addr` | ✅ | ✅ | ✅ |
| **TCP** | default | ✅ `TcpBackend` | ✅ `tcp_addr` | ✅ | ✅ | ✅ |
| **DoT** (RFC 7858) | `dot` | ✅ `DotBackend` | ✅ `dot_addr` | ✅ | ✅ | ✅ |
| **DoH** HTTP/1.1 + HTTP/2 (RFC 8484) | `doh` | ✅ `DohBackend` | ✅ `doh_addr` | ✅ | ✅ | ✅ |
| **DoH** HTTP/3 | `doh` | ✅ `Doh3Backend` | ✅ `doh3_addr` | ✅ | ✅ | ✅ |
| **DoQ** (RFC 9250) | `doq` | ✅ `DoqBackend` | ✅ `doq_addr` | ✅ | ✅ | ✅ |

✅ on a platform means CI on that OS runs `cargo check`, `cargo test`, and
rustdoc with warnings denied for that feature selection, and the tests
include a client and a listener round trip against a local loopback server
(self-signed certificates for the encrypted transports). CI does not contact
public resolvers.

> Binding a privileged port such as 53 is the host application's job; DNS
> Lattice needs no special privilege of its own.

## 🚀 Performance

### 🏆 Design Highlights

- **Cache hits never touch the network**: a hit takes one short lock on one
  shard of an in-memory store, clones a reference, and returns; concurrent
  hits on other shards do not wait for each other. The hook still runs
  first, upstreams do not.
- **A cache that cannot grow without bound**: the store holds a fixed
  number of bytes (16 MiB by default) and evicts on every insert, expired
  entries first, so a flood of one-off names cannot push out the names that
  are asked for again and again.
- **One task per request, no shared worker**: the server spawns a Tokio task
  per UDP datagram, per TCP/DoT/DoH connection, and per DoQ stream, all
  sharing one `Arc<Resolver>`.
- **No background threads or queues**: the resolver owns no threads or
  tasks, and observability callbacks run synchronously after the cache
  shard lock is released.
- **Pay only for the transports you use**: without `dot`, `doh`, or `doq`
  the build has no TLS, HTTP, or QUIC dependency.

Current limits, stated plainly:

- every upstream query opens a fresh socket or connection (UDP socket, TCP
  or TLS connection, DoH client, QUIC connection); there is no connection
  pooling yet;
- by default `UdpBackend` adds no EDNS0/OPT record of its own: it forwards
  the query unchanged, so a query without one gets UDP answers of at most
  512 bytes (larger ones fall back to TCP), while a query that carries one
  can get answers up to the size it advertises.
  `UdpBackend::with_edns_udp_payload_size` opts in to adding an OPT record
  to queries that have none (retrying once without it after `FORMERR` or
  `NOTIMP`, and removing it from the answer);
- the inbound server answers UDP EDNS(0) clients with at most
  min(client payload size raised to 512, 1232 bytes)
  (`ServerBuilder::edns_udp_payload_size`
  changes the 1232) and non-EDNS clients with at most 512 bytes; larger
  answers are sent empty with `TC=1`, so clients retry over TCP;
- the answer cache holds at most about 16 MiB by default
  (`CacheConfig::max_bytes`; an estimate of heap use, not an exact
  allocator figure) and has no background sweep: an expired entry is
  removed when its question is asked again or when an insert needs room.
  Concurrent identical misses are merged into one upstream query (see
  "Cache semantics").

### 📊 Benchmarks

A benchmark harness comparing DNS Lattice with
[hickory-resolver](https://github.com/hickory-dns/hickory-dns) is in
progress. No numbers are published yet; its results table will appear here.

## 📦 Installation

```toml
[dependencies]
# UDP and TCP only: no TLS, HTTP, or QUIC dependencies
dns-lattice = "1.1.3"
tokio = { version = "1.53.1", features = ["rt-multi-thread", "macros"] }
```

Add encrypted transports only when needed. The features are independent and
default-off:

```toml
# DNS-over-TLS
dns-lattice = { version = "1.1.3", features = ["dot"] }

# DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3
dns-lattice = { version = "1.1.3", features = ["doh"] }

# DNS-over-QUIC, without the HTTP stack
dns-lattice = { version = "1.1.3", features = ["doq"] }

# Everything
dns-lattice = { version = "1.1.3", features = ["dot", "doh", "doq"] }
```

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3;
- `doq` — DNS-over-QUIC.

Implementing `RouteHook` or `UpstreamBackend` also needs
`async-trait = "0.1"` in your own dependencies.

## 🎓 Quick Start

### UDP Resolver + Server

Use canonical domain modules; the facade intentionally exposes no flat root
aliases.

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

`Resolver` owns routing/cache/failover. `Server` owns inbound listening and
framing. `UpstreamBackend` implementations own outbound transport execution.

## 📚 Examples

### Split DNS with Failover

```rust,no_run
use std::{net::SocketAddr, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    model::{DomainPattern, SplitDnsPolicy, UpstreamGroupId},
    upstream::{TcpBackend, TcpBackendConfig, UdpBackend, UdpBackendConfig},
};

fn udp(server: &str) -> UdpBackend {
    UdpBackend::new(UdpBackendConfig {
        server: server.parse::<SocketAddr>().unwrap(),
        timeout: Duration::from_secs(2),
        bind_addr: None,
    })
}

fn build() -> Result<Resolver> {
    let corp = UpstreamGroupId::new("corp");
    let public = UpstreamGroupId::new("public");

    let policy = SplitDnsPolicy::builder()
        .rule(DomainPattern::parse("corp.internal")?, corp.clone()) // corp.internal and below
        .default_group(public.clone())
        .build();

    Ok(Resolver::builder(policy)
        .backend(
            corp,
            TcpBackend::new(TcpBackendConfig {
                server: "10.0.0.53:53".parse().unwrap(),
                connect_timeout: Duration::from_secs(2),
                read_timeout: Duration::from_secs(2),
            }),
        )
        // Tried in order: 9.9.9.9 only after 1.1.1.1 times out or fails
        // with a transport error.
        .backend(public.clone(), udp("1.1.1.1:53"))
        .backend(public, udp("9.9.9.9:53"))
        .build())
}
```

### DNS-over-TLS Upstream (`dot`)

```rust,no_run
use std::time::Duration;

use dns_lattice::{
    engine::Resolver,
    model::{SplitDnsPolicy, UpstreamGroupId},
    upstream::{DotBackend, DotBackendConfig},
};

fn build() -> Resolver {
    let group = UpstreamGroupId::new("encrypted");
    let dot = DotBackend::new(DotBackendConfig::with_webpki_roots(
        "1.1.1.1:853".parse().unwrap(),
        "cloudflare-dns.com".try_into().unwrap(), // SNI and certificate name
        Duration::from_secs(3),                   // TCP connect
        Duration::from_secs(5),                   // TLS handshake and each read/write
    ));

    Resolver::builder(SplitDnsPolicy::builder().default_group(group.clone()).build())
        .backend(group, dot)
        .build()
}
```

`DoqBackendConfig::with_webpki_roots` works the same way for DoQ; DoH takes a
`DohBackendConfig` / `Doh3BackendConfig` with the endpoint URI and a
`rustls` client configuration.

### Fake IP

```rust,no_run
use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use dns_lattice::{
    core::Result,
    engine::Resolver,
    fakeip::{FakeIpPolicy, FakeIpPool},
    model::{DomainPattern, SplitDnsPolicy},
};

fn build() -> Result<Resolver> {
    let pool = Arc::new(
        FakeIpPool::builder()
            .ipv4_range(Ipv4Addr::new(198, 18, 0, 0), Ipv4Addr::new(198, 19, 255, 255))
            .ttl(Duration::from_secs(300))
            .build()?,
    );
    let policy = FakeIpPolicy::builder()
        .rule(DomainPattern::parse("example.com")?)
        .build();

    // A queries for example.com and its subdomains get pool addresses; AAAA
    // gets a local NODATA because this pool has no IPv6 range.
    Ok(Resolver::builder(SplitDnsPolicy::builder().build())
        .fake_ip(pool, policy)
        .build())
}
```

### Dynamic Route Hook

```rust,no_run
use async_trait::async_trait;
use dns_lattice::{
    hooks::{RouteDecision, RouteHook, RouteHookError, RouteRequest},
    model::UpstreamGroupId,
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
```

Install it with `ResolverBuilder::route_hook(PreferFiltered)`.

### Observability Sink

```rust,no_run
use std::sync::Arc;

use dns_lattice::{
    engine::Resolver,
    model::SplitDnsPolicy,
    observability::{ObservabilitySink, ObserveEvent},
};

struct PrintSink;

impl ObservabilitySink for PrintSink {
    fn record(&self, event: &ObserveEvent) {
        println!("{event:?}");
    }
}

fn build() -> Resolver {
    Resolver::builder(SplitDnsPolicy::builder().build())
        .observability_sink(Arc::new(PrintSink))
        .build()
}
```

### Graceful Shutdown

```rust,no_run
use std::sync::Arc;

use dns_lattice::{core::Result, engine::Resolver, server::ServerBuilder};

// Needs tokio's `signal` feature for `ctrl_c`.
async fn run(resolver: Arc<Resolver>) -> Result<()> {
    let server = ServerBuilder::new(resolver)
        .udp_addr("127.0.0.1:5353".parse().unwrap())
        .tcp_addr("127.0.0.1:5353".parse().unwrap())
        .bind()
        .await?;

    server
        .serve_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}
```

### Runnable Examples

Runnable examples live in
[`crates/dns-lattice/examples`](crates/dns-lattice/examples):

- `split_dns_policy` — matcher and static policy behavior;
- `message_round_trip` — DNS wire encode/decode;
- `resolver` — in-process resolver/cache behavior.

Run one with:

```bash
cargo run -p dns-lattice --example <name>
```

## 🔄 Resolver Pipeline

The resolver pipeline is explicit:

```text
DNS query
  → terminal Fake IP handling when selected
  → static split-DNS candidate
  → optional RouteHook
  → validate effective upstream group
  → route-scoped cache
  → ordered upstream failover
  → answer
```

Inbound listeners reuse the same resolver pipeline:

```text
Client → Server → Resolver → Cache/Policy/Hook/Fake IP → UpstreamBackend → Resolver → Server → Client
```

## 🔀 Split DNS and Matching

`dns-lattice-model` provides deterministic exact/suffix/wildcard matching and
`SplitDnsPolicy`. The resolver first obtains a static upstream-group candidate
from that policy.

The matching/model layer performs no network I/O and has no OS dependency.
Stage-0.6 hardening added deterministic property-style coverage for matcher
precedence, message parsing, and DNS name compression bounds.

## 🧊 Cache Semantics

The resolver has an in-memory TTL-respecting answer cache, including negative
caching. Ordinary cache identity includes the **effective upstream group**.
That matters when a route hook sends equal DNS questions to different routes:
an answer obtained from one group cannot be reused for another group. The
query's RD bit and EDNS DO bit (RFC 3225) are part of the identity too.

- **What is cached**: `NOERROR` answers with records, `NXDOMAIN`, and
  `NODATA`, only with opcode QUERY, `TC=0`, and an EDNS extended RCODE of 0.
  `SERVFAIL`, `REFUSED`, other error codes, truncated answers, and answers
  with a TTL of 0 are returned but never stored. Queries with more or fewer
  than one question, another opcode, or an EDNS Client Subnet option or any
  EDNS option other than NSID, COOKIE, TCP keepalive and Padding, bypass the
  cache and coalescing.
- **Coalescing**: concurrent misses for the same cache identity share one
  upstream query (`CacheConfig::coalesce(false)` turns this off). The first
  query leads, stores its answer, then hands it to the others, which are
  answered with their own id, question and RD bit, or receive its error. A
  waiting query emits no upstream events; the sink gets
  `CacheEvent::Coalesced` through `ObservabilitySink::record_cache`. If the
  leading `resolve` future is dropped, a waiting query takes over; nothing
  is spawned, so this works on any executor.
- **Lifetimes**: by default stored TTLs are capped at 86 400 s (positive)
  and 3 600 s (negative); `CacheConfig::positive_ttl` and
  `CacheConfig::negative_ttl` set other bounds. A positive entry lives for
  its lowest record TTL across all sections; a negative one for min(SOA TTL,
  SOA `MINIMUM`) (RFC 2308), or 60 s without an SOA
  (`CacheConfig::negative_ttl_without_soa` changes it; `None` stores no
  such answer).
- **Memory bound**: the store is split into shards, each with its own lock
  and an equal share of `CacheConfig::max_bytes` (16 MiB by default). Every
  insert evicts until its shard is back within its share: expired entries
  first, then entries that were never reused (S3-FIFO), so a flood of
  unique names, such as random-subdomain NXDOMAIN queries, leaves the
  popular names in place. The cache is never flushed as a whole to make
  room. An answer larger than an eighth of a shard's share is returned but
  not stored. `CacheConfig::disabled()` (or `max_bytes(0)`) keeps nothing.
- **Hits**: TTLs count down by the whole seconds since the answer was
  stored. A hit carries the current query's id, question, and RD bit, sets
  AA=0, and keeps every record in its original order.
- **Flushing**: `Resolver::clear_cache` removes everything,
  `Resolver::purge(name, rtype)` removes one name (every group, class and
  query shape; one record type, or all with `None`), and
  `Resolver::purge_subtree(zone)` removes a zone and everything below it,
  matching whole labels only (`ample.com` does not match `example.com`). Each
  returns the number of entries removed. A flush also stops queries already
  waiting on an upstream call from storing their answer; they are still
  answered. Use it after a network or VPN change.
- **Statistics**: `Resolver::cache_stats()` returns a `CacheStats` snapshot
  with `entries`, `bytes` (an estimate), `capacity_bytes`, `hits`, `misses`,
  `coalesced`, `inserts`, `evictions`, `expirations` and `oversized_rejected`.
  The counters are monotonic and survive a flush.
- **EDNS(0)**: the OPT record is removed before an answer is stored, so a
  hit never replays another client's OPT record. A hit for a query with an
  OPT record gets a fresh one (1232 bytes, version 0, the query's DO bit,
  no options); a hit for a query without one gets none.

Fake IP terminal answers bypass the ordinary answer cache; their lifetime is
owned by the Fake IP mapping.

## 🪝 Dynamic Route Hooks

`ResolverBuilder::route_hook` installs one caller-owned `RouteHook` for
ordinary queries. The hook receives the first DNS question and tentative
static group:

- `Use(group)` selects an existing, nonempty upstream group;
- `Abstain` keeps the static candidate.

A hook error, unknown group, or empty group fails resolution without silently
falling back to another static route. Hooks are selection-only: DNS Lattice
does not give them resolver/backend handles, cache authority, client transport
metadata, or OS/network side-effect capabilities.

Hook implementations own timeout, retry, cancellation cleanup, and any
external calls. Re-entering the same resolver from its hook is prohibited.

## 🎭 Fake IP

`fakeip::FakeIpPool` provides deterministic, concurrent synthetic IPv4/IPv6
state:

- inclusive IPv4 and/or IPv6 ranges;
- deterministic domain → address allocation/reuse;
- address → active-domain reverse lookup;
- per-family LRU eviction on exhaustion;
- required whole-second TTL and expiry;
- caller-owned process-local in-memory snapshot/restore.

`ResolverBuilder::fake_ip` explicitly enables local synthesis through a
`FakeIpPolicy`:

- matching IN A/AAAA → local synthetic answer;
- selected but disabled address family → local NODATA;
- canonical in-range IN PTR → active name or NXDOMAIN.

Fake IP answers are terminal before static routing, hooks, ordinary cache, and
upstream calls. Their DNS TTL never exceeds the mapping's remaining lifetime.

DNS Lattice intentionally does **not** define durable Fake IP persistence or a
snapshot serialization format.

## 📡 Observability

`ResolverBuilder::observability_sink` accepts an optional
`observability::ObservabilitySink`. The resolver emits immutable, bounded
events for the important state transitions in the pipeline, including:

- query receipt;
- Fake IP terminal handling;
- static/effective route and hook outcomes;
- cache hit/miss;
- upstream attempts/outcomes;
- timeout and terminal error paths.

Cache signals that are not part of this ordered stream, such as a query
joining another query's in-flight upstream call, arrive as
`observability::CacheEvent` through the defaulted
`ObservabilitySink::record_cache` method; a sink that does not override it
ignores them.

The sink is non-authoritative. It cannot alter routing, answers, cache state,
or retries; it receives no resolver/backend handles; resolver locks are
released before callbacks run; callback panics are isolated from resolver
correctness. DNS Lattice does not require a logging/tracing framework or own a
background telemetry queue.

## 🔐 Upstream Transports

The resolver tries backends registered in an upstream group in registration
order. Timeout/transport/TLS failures can fail over to the next backend. If
all backends fail, the last error is returned and no successful answer is
cached.

| Transport | Feature | Implementation notes |
|---|---|---|
| UDP | default | Falls back to TCP on `TC=1` |
| TCP | default | RFC 1035 length-prefixed framing |
| DoT | `dot` | `rustls` / `tokio-rustls` |
| DoH HTTP/1.1 + HTTP/2 | `doh` | `hyper` / `hyper-rustls` |
| DoH HTTP/3 | `doh` | `h3` / `quinn`, ALPN `h3` |
| DoQ | `doq` | `quinn`, ALPN `doq` |

DoQ and HTTP/3 use QUIC/TLS 1.3. TCP DoH supports HTTP/1.1 and HTTP/2 over
TLS 1.2/1.3 according to the supplied configuration.

## 🖥️ Inbound Server

`Server` / `ServerBuilder` provide an embeddable inbound DNS server over a
shared `Arc<Resolver>`:

- UDP/TCP in the default build;
- DoT through `ServerBuilder::dot_addr` with `dot`;
- DoH HTTP/1.1/HTTP/2 through `ServerBuilder::doh_addr` with `doh`;
- DoH HTTP/3 through `ServerBuilder::doh3_addr` with `doh`;
- DoQ through `ServerBuilder::doq_addr` with `doq`.

The host application supplies TLS/QUIC server configuration and certificate
material. DNS Lattice does not provision certificates and does not own
privileged-port setup.

## ✅ Feature and Platform Constraints

MSRV: **Rust 1.93**.

CI validates the supported facade surface on:

- Linux;
- Windows;
- macOS.

CI runs workspace formatting, linting, checking, tests, and docs, plus strict
per-feature `check`/`test`/rustdoc coverage for:

```text
--no-default-features
dot
doh
doq
--all-features
```

CI also verifies workspace package contents and runs a hermetic regression of
the release automation. Those checks do not publish crates.

## 📋 Capability Status

| Capability | Status |
|---|:---:|
| DNS message encode/decode and name decompression | ✅ |
| Exact/suffix/wildcard domain matcher | ✅ |
| Static split-DNS policy | ✅ |
| Resolver + TTL/negative cache | ✅ |
| Byte-bounded sharded cache, configurable TTL limits | ✅ |
| Route-scoped cache identity | ✅ |
| UDP/TCP upstreams | ✅ |
| DoT/DoH/DoQ upstreams | ✅ |
| Ordered upstream failover | ✅ |
| UDP/TCP inbound server | ✅ |
| DoT/DoH/DoH3/DoQ inbound server | ✅ |
| Fake IP pool + resolver synthesis | ✅ |
| Dynamic `RouteHook` | ✅ |
| Structured `ObservabilitySink` | ✅ |
| Linux/Windows/macOS feature-matrix validation | ✅ |
| Package/release automation hardening | ✅ |
| Stable public API / SemVer guarantee | ✅ |

## 🤝 Comparison

[hickory-resolver](https://docs.rs/hickory-resolver) is the established
general-purpose DNS resolver for Rust. The two aim at different jobs: hickory
resolves names the way the operating system would, DNS Lattice routes and
serves DNS inside an application. Claims about hickory below come from its
docs.rs page (version 0.26.3).

| Feature | DNS Lattice | hickory-resolver |
|---------|-------------|------------------|
| **Purpose** | Resolver engine plus inbound server in one crate | Stub resolver (serving is a separate crate, `hickory-server`) |
| **UDP / TCP** | ✅ Default build | ✅ Default build |
| **DoT / DoH / DoH3 / DoQ upstreams** | ✅ `dot`, `doh`, `doq` features | ✅ `tls-*`, `https-*`, `h3-*`, `quic-*` features |
| **TLS crypto provider** | `aws-lc-rs` | `aws-lc-rs` or `ring` |
| **Inbound DoT / DoH / DoQ listener** | ✅ Built in | ➖ Not part of the resolver crate |
| **Per-domain split DNS to upstream groups** | ✅ `SplitDnsPolicy` | ➖ Not described in its docs |
| **Fake IP** | ✅ Built in | ➖ Not described in its docs |
| **Per-query routing hook** | ✅ `RouteHook` | ➖ Not described in its docs |
| **DNSSEC validation** | ❌ | ✅ `dnssec-*` features |
| **System resolver config** (`/etc/resolv.conf`, Windows) | ❌ By design; the host configures everything | ✅ `system-config` (default) |
| **Upstream connection reuse** | ❌ New connection per query | ✅ Name-server pool |
| **EDNS0 on UDP** | ➖ The inbound server answers EDNS clients with up to 1232 bytes (configurable), with `FORMERR`/`BADVERS` handled locally; `UdpBackend` forwards the client's OPT record and, unless `with_edns_udp_payload_size` opts in, adds none | Not compared |
| **Throughput and latency** | Not yet benchmarked | Not yet benchmarked |

## 🛠️ API Overview

### Public Modules

Canonical public paths are:

| Module | Purpose |
|---|---|
| `dns_lattice::core` | Shared typed errors/results |
| `dns_lattice::model` | DNS messages, records, names, matchers, policies |
| `dns_lattice::engine` | `Resolver` / `ResolverBuilder` |
| `dns_lattice::cache` | `CacheConfig`: cache memory bound, shards, TTL limits |
| `dns_lattice::upstream` | Outbound backend trait and transports |
| `dns_lattice::server` | Inbound listener configuration/lifecycle |
| `dns_lattice::fakeip` | Fake IP pool, policy, TTL, snapshots |
| `dns_lattice::hooks` | Dynamic route-selection hook |
| `dns_lattice::observability` | Structured resolver events/sink |

### Key Items

| Item | Purpose |
|------|---------|
| `Resolver::builder(SplitDnsPolicy)` | Start a resolver from a split-DNS policy |
| `ResolverBuilder::backend(group, backend)` | Register a backend in a group; order sets failover order |
| `ResolverBuilder::fake_ip(pool, policy)` | Enable local Fake IP answers |
| `ResolverBuilder::route_hook` / `observability_sink` | Install the optional hook and event sink |
| `Resolver::resolve(&Message)` | Resolve one decoded query |
| `ServerBuilder::new(Arc<Resolver>)` | Start an inbound server; add `udp_addr`, `tcp_addr`, `dot_addr`, `doh_addr`, `doh3_addr`, `doq_addr` |
| `ServerBuilder::bind` → `Server::serve` / `serve_until` | Bind every listener, then serve until dropped or until a shutdown future resolves |
| `UpstreamBackend` | The async trait every outbound transport implements |
| `Message::decode` / `encode` | DNS wire format |

### Workspace Crates

DNS Lattice is published as three crates:

| Crate | Responsibility |
|---|---|
| [`dns-lattice`](crates/dns-lattice/README.md) | Public facade plus resolver/server runtime implementation |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | DNS message model, names, matcher, split-DNS policy |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Shared typed `Error` / `Result` boundary |

Most applications should depend only on `dns-lattice`.

## 📖 Documentation

- **API reference**: [docs.rs/dns-lattice](https://docs.rs/dns-lattice)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Roadmap**: [ROADMAP.md](ROADMAP.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Support and security**: [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md)

## 🐛 Troubleshooting

<details>
<summary><b><code>Error::NoRoute</code> from <code>resolve</code></b></summary>

No split-DNS rule matched the name and the policy has no default group, the
query had no question, or the selected group (static or chosen by a hook)
has no backend registered. Add a `default_group`, or register a backend for
every group your rules and hook can return.
</details>

<details>
<summary><b><code>bind</code> fails with <code>Error::Transport</code></b></summary>

The address is already in use, invalid, or needs privileges (for example
port 53 on Unix). DNS Lattice does not special-case privileged ports; run on
an unprivileged port such as 5353, or grant your process the right to bind
the port.
</details>

<details>
<summary><b>Large answers are empty with the <code>TC</code> bit set</b></summary>

The inbound UDP listener answers a client without an EDNS0 OPT record with at
most 512 bytes, and an EDNS0 client with at most the smaller of its advertised
payload size and the server maximum (1232 bytes by default,
`ServerBuilder::edns_udp_payload_size`). For a larger answer it sends an empty,
truncated response (keeping the OPT record for an EDNS0 client) and the client
is expected to retry over TCP; also listen on TCP (`tcp_addr`) at the same
address. `UdpBackend` performs that TCP retry itself; to avoid it for most
upstream answers, call `UdpBackend::with_edns_udp_payload_size` so queries
without an OPT record advertise a larger UDP payload to the upstream.
</details>

<details>
<summary><b>DoQ or DoH over HTTP/3 fails the handshake</b></summary>

QUIC requires TLS 1.3 and the right ALPN. `DoqBackendConfig::with_webpki_roots`
sets `doq` for you; a hand-built client `tls_config` must include `doq`
itself. On the server side, the `quinn::ServerConfig` passed to `doq_addr`
must advertise `doq`, and the one passed to `doh3_addr` must advertise `h3`.
For `doh_addr`, configure ALPN `h2` and `http/1.1`.
</details>

<details>
<summary><b>A panic about a missing Tokio runtime</b></summary>

Every built-in backend and listener does socket I/O through Tokio, so call
`Resolver::resolve`, `ServerBuilder::bind`, and `Server::serve` from inside
a Tokio runtime (for example under `#[tokio::main]`).
</details>

## 🌐 The Lattice Ecosystem

| Crate | Purpose |
| --- | --- |
| [net-lattice](https://github.com/F000NKKK/net-lattice) | OS networking inspection and configuration (routes, DNS, interfaces) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP tunnel interfaces |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Programmable DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Policy compiler: rules to platform-neutral network plans |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Application-facing SDK composing the crates above |

DNS Lattice does not mutate OS DNS settings, manage TUN/TAP devices, compile a
rule language, or ship a standalone daemon product. Those responsibilities
belong to the host application or sibling Lattice components.

## 🗺️ Current Status and Roadmap

Completed:

1. **0.0** — repository/architecture baseline;
2. **0.1** — core DNS model;
3. **0.2** — resolver and static split DNS;
4. **0.3** — upstream transports, failover, inbound server;
5. **0.4** — Fake IP;
6. **0.5** — dynamic route hooks;
7. **0.6** — hardening, cross-platform validation, observability, package and
   release checks;
8. **1.0** — audited/froze the public API, established the stable SemVer
   contract, and published the first stable release (`dns-lattice`,
   `dns-lattice-core`, `dns-lattice-model` `1.0.0` on crates.io).

The public API is now frozen: within the `1.x` line, additive changes land as
minor releases and fixes as patch releases; a breaking change requires an
explicit major version bump.

See [ROADMAP.md](ROADMAP.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the
full delivery and contract details.

## 🙏 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[SUPPORT.md](SUPPORT.md) for project support status.

```bash
git clone https://github.com/F000NKKK/dns-lattice.git
cd dns-lattice
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test -p dns-lattice --no-default-features --features doq   # one feature on its own
```

No test needs privileges or network access beyond loopback.

## 📄 License

Licensed under the [Mozilla Public License 2.0](LICENSE).

## 🌟 Acknowledgments

- [`rustls`](https://github.com/rustls/rustls), [`quinn`](https://github.com/quinn-rs/quinn),
  [`hyper`](https://github.com/hyperium/hyper), and [`h3`](https://github.com/hyperium/h3),
  which carry the encrypted transports
- [Tokio](https://tokio.rs), which runs every socket
- [hickory-dns](https://github.com/hickory-dns/hickory-dns), the reference
  point for DNS in Rust

---

<div align="center">

**[⬆ Back to Top](#top)**

Part of the Lattice networking stack

</div>
