# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Stage 0.3 Track A (upstream transport, part 1): new public, async
  `dns_lattice::upstream` module — `UpstreamBackend` trait (replacing
  stage 0.2's crate-private, synchronous `engine::UpstreamBackend`,
  ADR-0009) plus baseline `UdpBackend`/`TcpBackend` implementations over
  `tokio`. No EDNS0/OPT support yet; `UdpBackend` falls back to a TCP query
  when a response's `TC` bit is set. See ADR-0011 (`DL-A-12`) for the full
  design rationale.
- **Breaking:** `Resolver::resolve` is now `async fn` and must be called
  from inside a `tokio` runtime; `ResolverBuilder::backend` now stores an
  ordered list of backends per upstream group (only the first is used this
  stage — later tracks add failover across the rest).
- New `dns_lattice_core::Error` variants: `Timeout` and `Transport(String)`,
  produced by the new UDP/TCP backends.

## [0.2.0] - 2026-08-02

- Stage 0.2 (resolver engine and static split DNS): `dns-lattice`'s new
  `engine` module (`Resolver`, `ResolverBuilder`) — in-process
  construct/resolve, static split-DNS routing via `SplitDnsPolicy`, a new
  `dns_lattice_core::Error::NoRoute` variant for unroutable queries, and an
  in-memory TTL-respecting answer cache including RFC 2308 negative
  caching. No real network transport yet.

## [0.1.0] - 2026-08-02

- Repository bootstrap: workflow, policies, and packaging scaffolding.
- Stage 0.1 (core model): `dns-lattice-core` (shared `Error`/`Result`) and
  `dns-lattice-model` (DNS message, zone/domain matcher, split-DNS policy
  types) crates, with `dns-lattice` as the facade crate re-exporting them.
