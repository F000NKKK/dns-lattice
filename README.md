# DNS Lattice

**Languages**

🇺🇸 **English** | 🇷🇺 [Русский](README.ru.md)

[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org)
[![crates.io](https://img.shields.io/crates/v/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice)](https://docs.rs/dns-lattice)
[![Downloads](https://img.shields.io/crates/d/dns-lattice.svg)](https://crates.io/crates/dns-lattice)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](Cargo.toml)

**DNS Lattice** is a programmable, embeddable DNS resolver/server engine for
Rust. It provides split DNS, caching, Fake IP, dynamic route selection,
structured observability, and UDP/TCP/DoT/DoH/DoQ transports behind one typed
library API.

Think of it as the DNS equivalent of an embeddable HTTP server core: the host
application owns the process and configuration, while DNS Lattice owns DNS
protocol handling, resolution, serving, routing, cache behavior, and transport
execution.

> **Status:** stages **0.0 through 0.6 are complete**. Stage 0.6 defines the
> `0.6.x` hardening release line and has no remaining implementation work. The
> repository release script owns the mechanical `0.6.0` Cargo version bump and
> publication. The next development milestone is **1.0**, which freezes and
> audits the public API before the first stable release. Until `1.0.0`, the API
> remains pre-1.0 and may change.

## Why DNS Lattice

Applications that need custom DNS behavior often end up combining several
concerns manually: DNS wire parsing, split-DNS policy, cache semantics,
transport fallback, encrypted DNS, Fake IP state, server listeners, and
application-specific routing. DNS Lattice keeps those concerns separate but
composable.

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

## Workspace

DNS Lattice is published as three crates:

| Crate | Responsibility |
|---|---|
| `dns-lattice` | Public facade plus resolver/server runtime implementation |
| `dns-lattice-model` | DNS message model, names, matcher, split-DNS policy |
| `dns-lattice-core` | Shared typed `Error` / `Result` boundary |

Most applications should depend only on `dns-lattice`.

## Installation

Baseline UDP/TCP support has no TLS/HTTP/QUIC feature requirement:

```toml
[dependencies]
dns-lattice = "0.6"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Enable encrypted transports only when needed:

```toml
[dependencies]
dns-lattice = { version = "0.6", features = ["dot", "doh", "doq"] }
```

Cargo features are independent and default-off:

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3;
- `doq` — DNS-over-QUIC.

## Quick start: UDP resolver + server

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

# async fn run() -> Result<()> {
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
# Ok(())
# }
```

`Resolver` owns routing/cache/failover. `Server` owns inbound listening and
framing. `UpstreamBackend` implementations own outbound transport execution.

## Public modules

Canonical public paths are:

| Module | Purpose |
|---|---|
| `dns_lattice::core` | Shared typed errors/results |
| `dns_lattice::model` | DNS messages, records, names, matchers, policies |
| `dns_lattice::engine` | `Resolver` / `ResolverBuilder` |
| `dns_lattice::upstream` | Outbound backend trait and transports |
| `dns_lattice::server` | Inbound listener configuration/lifecycle |
| `dns_lattice::fakeip` | Fake IP pool, policy, TTL, snapshots |
| `dns_lattice::hooks` | Dynamic route-selection hook |
| `dns_lattice::observability` | Structured resolver events/sink |

## Split DNS and matching

`dns-lattice-model` provides deterministic exact/suffix/wildcard matching and
`SplitDnsPolicy`. The resolver first obtains a static upstream-group candidate
from that policy.

The matching/model layer performs no network I/O and has no OS dependency.
Stage-0.6 hardening adds deterministic property-style coverage for matcher
precedence, message parsing, and DNS name compression bounds.

## Cache semantics

The resolver has an in-memory TTL-respecting answer cache, including negative
caching. Ordinary cache identity includes the **effective upstream group**.
That matters when a route hook sends equal DNS questions to different routes:
an answer obtained from one group cannot be reused for another group.

Fake IP terminal answers bypass the ordinary answer cache; their lifetime is
owned by the Fake IP mapping.

## Dynamic route hooks

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

### Hook example

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

## Fake IP

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

## Observability

`ResolverBuilder::observability_sink` accepts an optional
`observability::ObservabilitySink`. The resolver emits immutable, bounded
events for the important state transitions in the pipeline, including:

- query receipt;
- Fake IP terminal handling;
- static/effective route and hook outcomes;
- cache hit/miss;
- upstream attempts/outcomes;
- timeout and terminal error paths.

The sink is non-authoritative. It cannot alter routing, answers, cache state,
or retries; it receives no resolver/backend handles; resolver locks are
released before callbacks run; callback panics are isolated from resolver
correctness. DNS Lattice does not require a logging/tracing framework or own a
background telemetry queue.

## Upstream transports

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

## Inbound server

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

## Feature and platform constraints

MSRV: **Rust 1.93**.

Stage 0.6 validates the supported facade surface on:

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

## Capability status

| Capability | Status |
|---|:---:|
| DNS message encode/decode and name decompression | ✅ |
| Exact/suffix/wildcard domain matcher | ✅ |
| Static split-DNS policy | ✅ |
| Resolver + TTL/negative cache | ✅ |
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
| Stable public API / SemVer guarantee | ⏳ Stage 1.0 |

## Lattice ecosystem boundaries

DNS Lattice is one component of the wider Lattice networking stack:

```text
net-lattice      OS network configuration and inspection
tunnel-lattice   TUN/TAP data-plane primitives
dns-lattice      DNS resolver/server control plane
flow-lattice     Policy compiler
sdk-lattice      Application-facing composition
```

DNS Lattice does not mutate OS DNS settings, manage TUN/TAP devices, compile a
rule language, or ship a standalone daemon product. Those responsibilities
belong to the host application or sibling Lattice components.

## Current status and roadmap

Completed:

1. **0.0** — repository/architecture baseline;
2. **0.1** — core DNS model;
3. **0.2** — resolver and static split DNS;
4. **0.3** — upstream transports, failover, inbound server;
5. **0.4** — Fake IP;
6. **0.5** — dynamic route hooks;
7. **0.6** — hardening, cross-platform validation, observability, package and
   release checks.

Stage 0.6 has no remaining implementation work. The `0.6.0` release operation
is the repository's mechanical version bump/publication step.

Next:

8. **1.0** — audit/freeze the public API, establish the stable SemVer contract,
   perform final package/docs.rs verification, and publish the first stable
   release.

See [ROADMAP.md](ROADMAP.md) and [ARCHITECTURE.md](ARCHITECTURE.md) for the
full delivery and contract details.

## Examples

Runnable examples live in
[`crates/dns-lattice/examples`](crates/dns-lattice/examples):

- `split_dns_policy` — matcher and static policy behavior;
- `message_round_trip` — DNS wire encode/decode;
- `resolver` — in-process resolver/cache behavior.

Run one with:

```bash
cargo run -p dns-lattice --example <name>
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution requirements,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[SUPPORT.md](SUPPORT.md) for project support status.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
