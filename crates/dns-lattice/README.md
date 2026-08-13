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
  `TC` bit is set). DoT/DoH/DoQ backends, failover across upstreams within
  a group, and the inbound server listener are still planned.

Server, Fake IP, and dynamic routing hook capabilities are planned for
later stages; see `ROADMAP.md` in the repository root.

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
far landed the public async `upstream` trait plus baseline UDP/TCP
backends. DoT/DoH/DoQ backends, upstream failover, the inbound server
listener, Fake IP, and dynamic routing hooks are not implemented yet.
Types may change without notice until the first stable release.
