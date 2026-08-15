# dns-lattice

Programmable, embeddable DNS resolver/server engine for Rust: split DNS,
TTL-aware caching, Fake IP, dynamic route selection, structured observability,
and UDP/TCP/DoT/DoH/DoQ transports.

This is the recommended application-facing crate in the DNS Lattice workspace.
It re-exports the protocol/model and shared error layers through canonical
domain modules and contains the resolver/server runtime implementation.

## Installation

Baseline UDP/TCP:

```toml
[dependencies]
dns-lattice = "0.6"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Encrypted DNS transports are opt-in:

```toml
[dependencies]
dns-lattice = { version = "0.6", features = ["dot", "doh", "doq"] }
```

Features are independent and default-off:

- `dot` — DNS-over-TLS;
- `doh` — DNS-over-HTTPS over HTTP/1.1, HTTP/2, and HTTP/3;
- `doq` — DNS-over-QUIC.

MSRV: Rust 1.93.

## Public surface

Use canonical domain modules; flat root aliases are intentionally not exposed.

- `dns_lattice::core` — shared `Error` / `Result`;
- `dns_lattice::model` — DNS messages, records, names, domain matcher,
  split-DNS policy, upstream-group identifiers;
- `dns_lattice::engine` — `Resolver` / `ResolverBuilder`;
- `dns_lattice::upstream` — `UpstreamBackend` and outbound transports;
- `dns_lattice::server` — `Server` / `ServerBuilder` and inbound listeners;
- `dns_lattice::fakeip` — synthetic-address pool, policy, TTL, snapshots;
- `dns_lattice::hooks` — dynamic route-selection hook;
- `dns_lattice::observability` — structured resolver event sink.

## Resolver pipeline

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

## Quick start

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
protocol framing. `UpstreamBackend` implementations own outbound transport
execution.

## Dynamic route hook

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

## Fake IP

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

## Observability

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

## Upstream transports

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

## Inbound server

`ServerBuilder` embeds a shared `Arc<Resolver>` and supports:

- UDP/TCP in the baseline build;
- `dot_addr` with `dot` for DoT;
- `doh_addr` with `doh` for HTTP/1.1/HTTP/2 DoH;
- `doh3_addr` with `doh` for HTTP/3 DoH;
- `doq_addr` with `doq` for DoQ.

The host provides TLS/QUIC server configuration and certificate material.
Binding privileged ports, configuring the OS resolver, and provisioning
certificates remain host responsibilities.

## Platform and validation contract

The 0.6 release surface is validated on Linux, Windows, and macOS. CI runs the
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

## Safety and responsibility boundaries

This crate performs ordinary socket/TLS/QUIC networking but does not mutate OS
DNS configuration or manage TUN/TAP devices. Those responsibilities belong to
the host application or sibling Lattice components.

Route hooks and observability sinks do not receive privileged runtime handles
from DNS Lattice. Applications that intentionally perform side effects from
their own hook/sink implementations are responsible for those effects.

## Status

Stages 0.0 through 0.6 are complete. This crate belongs to the `0.6.x` pre-1.0
release line, including Fake IP, dynamic route hooks, structured observability,
cross-platform feature validation, deterministic hardening coverage, and
package/release regression checks.

There is no remaining stage-0.6 implementation work. The next development
milestone is stage 1.0: audit and freeze the public API, establish the stable
SemVer contract, perform final package/docs.rs verification, and publish the
first stable release.

Until `1.0.0`, the public API may still change.

Repository: https://github.com/F000NKKK/dns-lattice

License: MPL-2.0.
