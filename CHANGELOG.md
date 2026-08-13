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
- Stage 0.3 Track B (upstream transport, part 2): two new default-off Cargo
  features on `dns-lattice`, `dot` and `doh`. `dot` adds `DotBackend`/
  `DotBackendConfig` (DNS-over-TLS, RFC 7858) over `rustls`/`tokio-rustls`;
  `doh` adds `DohBackend`/`DohBackendConfig`/`DohMethod` (DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats) over `hyper`/`hyper-rustls`. Both
  are independent and additive to the baseline UDP/TCP build, which keeps
  zero TLS/HTTP dependency weight unless explicitly opted into. New
  `dns_lattice_core::Error::Tls(String)` variant for TLS handshake/
  certificate/hostname-verification failures, distinct from `Transport`.
  See ADR-0012 (`DL-A-13`) for the full design rationale.
- Stage 0.3 Track C (upstream transport, part 3): new default-off `doq`
  Cargo feature on `dns-lattice` adding `DoqBackend`/`DoqBackendConfig`
  (DNS-over-QUIC, RFC 9250) over `quinn` (TLS 1.3 embedded in QUIC via
  `rustls`, sharing the workspace's `aws-lc-rs` crypto provider with
  `dot`/`doh`). Independent of `dot`/`doh`; opens a fresh QUIC connection
  per query in this stage (no pooling/reuse), one bidirectional stream per
  query, no 0-RTT. No new `dns_lattice_core::Error` variant — reuses
  `Tls`/`Transport` on the same boundary as `dot`/`doh`. See ADR-0013
  (`DL-A-14`) for the full design rationale.

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
