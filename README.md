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

> **Status:** Stages 0.1-0.2 have landed the DNS message model,
> zone/domain matcher, split-DNS policy types, and an in-process resolver
> (routing plus a TTL/negative-caching answer cache) across three crates —
> `dns-lattice-core`, `dns-lattice-model`, and the `dns-lattice` facade.
> `0.1.0` versions were published to reserve the crate names on crates.io;
> no public API is stable yet. See Current Status below.

## Overview

DNS resolution logic in Rust applications is usually either hand-rolled ad hoc, or pulled in as a heavyweight, fully async, transport-coupled resolver library. DNS Lattice aims to separate the protocol/policy plane (message parsing, zone matching, split-DNS routing, Fake IP) from transport concerns, so applications can embed exactly the DNS server or resolver behavior they need behind one strongly typed API.

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

Implemented (stage 0.1-0.2):

- Hand-rolled DNS message model: header, question, and resource-record encode/decode, including name (de)compression on decode
- Record types: A, AAAA, CNAME, PTR, NS, TXT, MX, SOA, plus a typed fallback for any other record type
- Zone/domain matcher with deterministic exact/suffix/wildcard precedence
- Static split-DNS policy types (`SplitDnsPolicy`) built on the matcher
- In-process `Resolver`: construct from a `SplitDnsPolicy`, route one query to an upstream group, and resolve it through a registered backend, with an in-memory TTL-respecting answer cache including RFC 2308 negative caching

Planned (see [ROADMAP.md](ROADMAP.md)):

- UDP/TCP/DoT/DoH/DoQ upstream backends and the inbound server listener (stage 0.3)
- Fake IP address pool with reverse lookup (stage 0.4)
- Dynamic routing hooks for caller-driven policy (stage 0.5)
- Cross-platform CI matrix, fuzz/property tests, observability sink (stage 0.6)

## Non-Goals

- DNS Lattice does not own OS-level DNS configuration mutation — that is [net-lattice](https://github.com/F000NKKK/net-lattice)'s responsibility.
- DNS Lattice does not compile a rule syntax — that is [flow-lattice](https://github.com/F000NKKK/flow-lattice)'s responsibility.
- DNS Lattice does not manage TUN/TAP devices — that is [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice)'s responsibility.
- DNS Lattice does not ship as a standalone server product (CLI, config file format, process supervision) — only the embeddable serving *engine* is in scope; packaging it as an installable daemon belongs to an application built on top, typically via [sdk-lattice](https://github.com/F000NKKK/sdk-lattice).

## Current Status

Stages 0.1-0.2 implementation of the [architecture](ARCHITECTURE.md)'s
module layout is covered by deterministic unit/doc tests, `clippy -D
warnings`, and verified `cargo package` listings for all three crates:

- `dns-lattice-core`'s `Error`/`Result` pair, hand-rolled `Display`/`std::error::Error`
- `dns-lattice-model`'s `message` (`Message`, `Header`, `Question`, `ResourceRecord`), `record` (`RecordType`, `Class`, `RData`), `matcher` (`DomainPattern`, `DomainMatcher<T>`), and `policy` (`SplitDnsPolicy`) modules
- the `dns-lattice` facade's `engine` module (`Resolver`, `ResolverBuilder`): in-process construct/resolve, static split-DNS routing, and an in-memory TTL-respecting/negative-caching answer cache — no real network transport yet

This gives a complete, tested DNS message model, a deterministic
zone/domain matcher, and an in-process resolver usable standalone today,
ahead of any real transport or server code. No real network I/O or Fake IP
exist yet — see Non-Goals for stage 0.2 in [ROADMAP.md](ROADMAP.md).

| Capability | Status |
|---|:---:|
| DNS message encode/decode | ✅ |
| Name (de)compression on decode | ✅ |
| Zone/domain matcher (exact/suffix/wildcard) | ✅ |
| Static split-DNS policy types | ✅ |
| Resolver engine / answer cache | ✅ |
| UDP/TCP/DoT/DoH/DoQ upstream + server listener | planned (0.3) |
| Fake IP pool | planned (0.4) |
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
4. **Stage 0.3: Upstream transport backends and server listener** — stabilized upstream backend trait, UDP/TCP baseline, DoT/DoH/DoQ behind Cargo features, fallback/failover across upstreams, inbound UDP/TCP/DoT/DoH/DoQ server listener.
5. **Stage 0.4: Fake IP pool** — deterministic synthetic address allocation, reverse lookup, LRU eviction, documented `tunnel-lattice` integration contract.
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
