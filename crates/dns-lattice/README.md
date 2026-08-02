# dns-lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## What it provides

- `dns-lattice-model`'s DNS message model (`Message`, `Header`, `Question`,
  `ResourceRecord`, `RData`), zone/domain matcher (`DomainPattern`,
  `DomainMatcher`), and split-DNS policy types (`SplitDnsPolicy`), re-exported
  through this facade crate.
- `dns-lattice-core`'s `Error`/`Result` pair.
- An in-process resolver entry point (`Resolver`, `ResolverBuilder`): route
  one query through a `SplitDnsPolicy` to an upstream group, then forward it
  to that group's backend. No in-memory answer cache and no real network
  transport yet — those land in a later slice of stage 0.2 / stage 0.3.

Server, upstream transports, Fake IP, and hook capabilities are planned for
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
landed the DNS message/matcher/policy model above; stage 0.2 is landing
incrementally, starting with the resolver's construct/resolve lifecycle and
static split-DNS routing (no cache yet). Server, real upstream transports,
Fake IP, and dynamic routing hooks are not implemented yet. Types may change
without notice until the first stable release.
