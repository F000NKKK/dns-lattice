# dns-lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## What it provides

- `dns-lattice-model`'s DNS message model (`Message`, `Header`, `Question`,
  `ResourceRecord`, `RData`), zone/domain matcher (`DomainPattern`,
  `DomainMatcher`), and split-DNS policy types (`SplitDnsPolicy`), re-exported
  through this facade crate.
- `dns-lattice-core`'s `Error`/`Result` pair.

Server, engine, upstream, Fake IP, and hook capabilities are planned for
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

Pre-0.1 stage: this crate has no stable API yet. Stage 0.1 (core model) has
landed the DNS message/matcher/policy model above; server, resolver engine,
upstream transports, Fake IP, and dynamic routing hooks are not implemented
yet. Types may change without notice until the first stable release.
