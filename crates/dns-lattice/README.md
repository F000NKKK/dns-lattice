<div align="center">

# 🧭 dns-lattice

### A Programmable, Embeddable DNS Resolver and Server Engine for Rust

[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![CI](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml/badge.svg)](https://github.com/F000NKKK/dns-lattice/actions/workflows/ci.yml)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/dns-lattice)

![Linux](https://img.shields.io/badge/Linux-supported-success)
![Windows](https://img.shields.io/badge/Windows-supported-success)
![macOS](https://img.shields.io/badge/macOS-supported-success)

[Overview](#-overview) • [Features](#-key-features) • [Feature Flags](#-feature-flags) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Pipeline](#-resolver-pipeline) • [Transports](#-upstream-transports)

</div>

---

## 📖 Overview

Programmable, embeddable DNS resolver/server engine for Rust: split DNS,
TTL-aware caching, Fake IP, dynamic route selection, structured observability,
and UDP/TCP/DoT/DoH/DoQ transports.

This is the recommended application-facing crate in the
[DNS Lattice](https://github.com/F000NKKK/dns-lattice) workspace. It
re-exports the protocol/model and shared error layers through canonical
domain modules and contains the resolver/server runtime implementation.

### 🎯 Why dns-lattice?

- **🔀 Split DNS first**: every query is routed to a named upstream group by
  deterministic exact/suffix/wildcard rules.
- **🧊 Route-scoped cache**: equal questions sent to different groups never
  share an answer.
- **🎭 Fake IP built in**, as a terminal answer path before routing.
- **🪝 Selection-only hooks**: pick the upstream group per question without
  receiving any resolver, backend, or OS handle.
- **🔐 Every transport, both directions**: UDP, TCP, DoT, DoH (HTTP/1.1,
  HTTP/2, HTTP/3), and DoQ, as upstream clients and inbound listeners.

## 🌟 Key Features

- ✅ `Resolver` / `ResolverBuilder`: static split DNS, optional route hook,
  TTL and negative cache scoped by upstream group, ordered failover
- ✅ `UpstreamBackend` with built-in UDP, TCP, DoT, DoH, DoH3, and DoQ
  backends; implement the trait for your own transport
- ✅ `Server` / `ServerBuilder`: inbound listeners on the same transports
  over a shared `Arc<Resolver>`, with `serve` and `serve_until`
- ✅ `FakeIpPool` / `FakeIpPolicy`: synthetic IPv4/IPv6 answers with reverse
  lookup, LRU eviction, TTLs, and snapshots
- ✅ `RouteHook` and `ObservabilitySink`: dynamic routing and structured
  events without giving away control

## 🎛️ Feature Flags

Features are independent and default-off:

| Feature | Adds | Main dependencies |
|---------|------|-------------------|
| *(none)* | UDP and TCP, client and server | `tokio` |
| `dot` | DNS-over-TLS | `rustls`, `tokio-rustls`, `webpki-roots` |
| `doh` | DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3 | `hyper`, `hyper-rustls`, `h3`, `quinn` |
| `doq` | DNS-over-QUIC, without the HTTP stack | `quinn`, `rustls`, `webpki-roots` |

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3;
- `doq` — DNS-over-QUIC.

MSRV: Rust 1.93.

## 📦 Installation

Baseline UDP/TCP:

```toml
[dependencies]
dns-lattice = "1.1.2"
tokio = { version = "1.53.1", features = ["rt-multi-thread", "macros"] }
```

Encrypted DNS transports are opt-in:

```toml
[dependencies]
dns-lattice = { version = "1.1.2", features = ["dot", "doh", "doq"] }
```

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

`Resolver` owns routing/cache/failover. `Server` owns inbound listening and
protocol framing. `UpstreamBackend` implementations own outbound transport
execution.

More examples (split DNS with failover, DoT, Fake IP, observability, graceful
shutdown) are in the
[project README](https://github.com/F000NKKK/dns-lattice#-examples).

## 🗂️ Public Surface

Use canonical domain modules; flat root aliases are intentionally not exposed.

| Module | Contents |
|--------|----------|
| `dns_lattice::core` | shared `Error` / `Result` |
| `dns_lattice::model` | DNS messages, records, names, domain matcher, split-DNS policy, upstream-group identifiers |
| `dns_lattice::engine` | `Resolver` / `ResolverBuilder` |
| `dns_lattice::upstream` | `UpstreamBackend` and outbound transports |
| `dns_lattice::server` | `Server` / `ServerBuilder` and inbound listeners |
| `dns_lattice::fakeip` | synthetic-address pool, policy, TTL, snapshots |
| `dns_lattice::hooks` | dynamic route-selection hook |
| `dns_lattice::observability` | structured resolver event sink |

## 🔄 Resolver Pipeline

For ordinary queries the resolver executes:

```text
static split-DNS candidate
  → optional RouteHook
  → validate effective upstream group
  → cache scoped to that group
  → ordered upstream failover
  → answer
```

Fake IP is a terminal path before ordinary routing/cache/upstreams when the
configured `FakeIpPolicy` selects the query.

### Cache identity

The in-memory answer cache respects DNS TTLs and negative caching. Ordinary
cache identity includes the effective upstream group. Equal DNS questions
routed to different groups cannot share an answer.

## 🪝 Dynamic Route Hook

`ResolverBuilder::route_hook` accepts one caller-owned `hooks::RouteHook`.
The hook receives the first DNS question and tentative static group:

- `RouteDecision::Use(group)` selects a registered, nonempty group;
- `RouteDecision::Abstain` preserves the static candidate.

A hook error, unknown selected group, or empty selected group returns a
resolver error without cache/upstream fallback. Hooks are selection-only and
receive no resolver/backend handles, client transport metadata, or OS/network
side-effect authority. Hook implementations own timeout, retry, cancellation
cleanup, and external integration.

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

Do not re-enter the same resolver from its route hook.

## 🎭 Fake IP

`FakeIpPool` provides deterministic concurrent synthetic-address state with:

- optional inclusive IPv4 and IPv6 ranges;
- deterministic domain → address allocation/reuse;
- reverse lookup of active mappings;
- per-family LRU eviction when a range is full;
- required whole-second TTL and expiry;
- caller-owned process-local in-memory snapshot/restore.

`ResolverBuilder::fake_ip(pool, policy)` makes synthesis explicit:

- matching IN A/AAAA → local synthetic response;
- selected but disabled family → local NODATA;
- canonical PTR inside a configured range → active mapping or NXDOMAIN.

These answers bypass the ordinary answer cache and upstreams, and their DNS TTL
never exceeds the mapping's remaining lifetime.

The crate deliberately does not serialize snapshots or provide durable Fake IP
persistence.

## 📡 Observability

`ResolverBuilder::observability_sink` accepts an optional
`observability::ObservabilitySink`. Events cover query receipt, Fake IP
terminal behavior, route/hook decisions, cache hit/miss, upstream attempts and
outcomes, timeouts, and terminal failures.

The sink is synchronous and non-authoritative:

- events are immutable and bounded;
- callbacks cannot modify routing, cache state, retries, or answers;
- callbacks receive no resolver/backend handles;
- resolver locks are released before callbacks run;
- callback panics are isolated from resolver correctness;
- the crate does not require a logging/tracing framework or own a background
  telemetry queue.

## 🔐 Upstream Transports

`UpstreamBackend` is async. Backends registered for one upstream group are
tried in registration order. Timeout/transport/TLS failures can fall over to
the next backend. If all fail, the last error is returned.

| Transport | Feature | Notes |
|---|---|---|
| UDP | default | Falls back to TCP when `TC=1` |
| TCP | default | RFC 1035 framed DNS |
| DoT | `dot` | `rustls` / `tokio-rustls` |
| DoH HTTP/1.1 + HTTP/2 | `doh` | `hyper` / `hyper-rustls` |
| DoH HTTP/3 | `doh` | `h3` / `quinn`, ALPN `h3`, TLS 1.3 |
| DoQ | `doq` | `quinn`, ALPN `doq`, TLS 1.3 |

Encrypted features are default-off so applications using only UDP/TCP do not
inherit TLS/HTTP/QUIC dependency weight.

## 🖥️ Inbound Server

`ServerBuilder` embeds a shared `Arc<Resolver>` and supports:

- UDP/TCP in the baseline build;
- `dot_addr` with `dot` for DoT;
- `doh_addr` with `doh` for HTTP/1.1/HTTP/2 DoH;
- `doh3_addr` with `doh` for HTTP/3 DoH;
- `doq_addr` with `doq` for DoQ.

The host provides TLS/QUIC server configuration and certificate material.
Binding privileged ports, configuring the OS resolver, and provisioning
certificates remain host responsibilities.

## ✅ Platform and Validation Contract

The supported surface is validated on Linux, Windows, and macOS. CI runs the
workspace format/lint/check/test/doc gates and strict facade check/test/rustdoc
for:

```text
--no-default-features
dot
doh
doq
--all-features
```

CI also lists workspace package contents and runs the hermetic release
automation regression. Validation does not publish crates.

## 🛡️ Safety and Responsibility Boundaries

This crate performs ordinary socket/TLS/QUIC networking but does not mutate OS
DNS configuration or manage TUN/TAP devices. Those responsibilities belong to
the host application or sibling Lattice components.

Route hooks and observability sinks do not receive privileged runtime handles
from DNS Lattice. Applications that intentionally perform side effects from
their own hook/sink implementations are responsible for those effects.

## 📌 Status

**Stable `1.x` releases are published** on crates.io. Stages 0.0 through 1.0
are complete: Fake IP, dynamic route hooks, structured observability,
cross-platform feature validation, deterministic hardening coverage,
package/release regression checks, full rustdoc coverage, and the
public-API freeze audit are all done.

Within the `1.x` line, ordinary SemVer now applies: additive changes are
minor releases, fixes are patch releases, and a breaking change requires an
explicit major version bump.

## 📖 Documentation

- **API reference**: [docs.rs/dns-lattice](https://docs.rs/dns-lattice)
- **Project**: [github.com/F000NKKK/dns-lattice](https://github.com/F000NKKK/dns-lattice)
- **Architecture**: [ARCHITECTURE.md](https://github.com/F000NKKK/dns-lattice/blob/main/ARCHITECTURE.md)
- **Changelog**: [CHANGELOG.md](https://github.com/F000NKKK/dns-lattice/blob/main/CHANGELOG.md)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE).
