# DNS Lattice roadmap

This roadmap sequences the design in `ARCHITECTURE.md`. It is the source of
current stage facts referenced by `index.md`, `AGENTS.md`, and the
repository's agent role profiles. Update this file whenever a stage starts,
completes, or changes scope, and keep it consistent with `ROADMAP.ru.md`.

Each stage below is broken down into one or more bounded implementation
slices when work starts; this file tracks stage-level status only, not
individual slices.

## Stage status legend

- `planned` — scoped here, work not yet started.
- `active` — work is in progress.
- `done` — the task's verification gates all passed and the work merged.

## Stage 0.0 — Audit, roadmap, architecture baseline

Status: done (this document and `ARCHITECTURE.md` are its output)

- Inventory the repository's current bootstrap state (this stage's audit).
- Record dependency direction and API boundaries against the other Lattice
  crates (see `ARCHITECTURE.md`).
- Establish the target module layout, data flow, and non-goals so stage 0.1
  has a design to implement against instead of inventing scope mid-slice.
- Non-goal: no source code, no public API, no crate release.

## Stage 0.1 — Core model

Status: planned

- DNS message model: query, answer, record types needed by the engine
  (evaluate reuse of an existing DNS protocol crate vs. hand-rolled types;
  record the decision as an ADR).
- Zone/domain matcher type (exact, suffix, wildcard) with deterministic
  precedence rules.
- Policy/configuration types consumed by the engine and by hooks.
- Deterministic unit tests for matcher precedence and message
  encode/decode round-trips.
- Non-goal: no network I/O, no cache, no Fake IP.

## Stage 0.2 — Resolver engine and static split DNS

Status: planned

- Resolver entry point: construct from config, resolve one query, shut down.
- Static split-DNS routing: match a query to an upstream group via the
  stage 0.1 matcher.
- In-memory answer cache respecting TTL, including negative caching.
- Fake in-process upstream backend for deterministic tests (ordinary tests
  use no real network, per repository CI policy).
- Non-goal: no real network transport yet, no dynamic hooks, no inbound
  server listener (the resolver is exercised in-process only at this
  stage).

## Stage 0.3 — Upstream transport backends and server listener

Status: planned

- `upstream` backend trait stabilized (from `ARCHITECTURE.md`).
- UDP and TCP upstream backends (baseline, no TLS/QUIC dependency).
- DoT and DoH upstream backends behind explicit Cargo features.
- DoQ upstream backend behind an explicit Cargo feature, if a maintained
  QUIC/HTTP-3 dependency is available for all target platforms; otherwise
  record the gap as an ADR and defer.
- Fallback/failover across upstreams within a group (see the failure-flow
  diagram in `ARCHITECTURE.md`).
- `server` inbound listener: UDP and TCP first, matching the crate's
  Kestrel-style embeddable-server goal from `ARCHITECTURE.md`; DoT/DoH/DoQ
  listeners behind the same Cargo features as their upstream counterparts.
- Non-goal: no platform-specific privileged transport (e.g. raw sockets,
  binding privileged ports) — that stays the composing application's
  responsibility, typically via `net-lattice`.

## Stage 0.4 — Fake IP pool

Status: planned

- Deterministic allocation of synthetic IPv4/IPv6 addresses per domain.
- Reverse lookup (address -> domain) and explicit not-found handling.
- Pool exhaustion policy (LRU eviction, as recorded in `ARCHITECTURE.md`).
- Integration contract documented for `tunnel-lattice` consumers, without a
  compile-time dependency on that crate.

## Stage 0.5 — Dynamic routing hooks

Status: planned

- Stable hook trait(s) letting a caller (e.g. `flow-lattice`) influence
  per-query routing without `dns-lattice` depending on it at compile time.
- Hook composition and precedence rules against static split-DNS rules.
- Example/integration test simulating a policy-driven hook end to end.

## Stage 0.6 — Hardening and platform validation

Status: planned

- Cross-platform CI matrix (Linux/Windows/macOS) exercising every backend
  feature combination.
- Fuzz/property tests for message parsing and matcher precedence.
- Observability sink trait finalized; structured events documented.
- Full documentation sync: rustdoc, crate README, root EN/RU docs,
  CHANGELOG, SECURITY, SUPPORT, CONTRIBUTING.

## Stage 1.0 — Stable public API and first release

Status: planned

- Public API frozen; SemVer commitment recorded.
- `cargo package` verified for the crate; docs.rs build verified.
- First published release on crates.io.
- `index.md` and this roadmap updated to reflect the released stage instead
  of "no release has been published yet".

## Explicitly out of scope for this crate's roadmap

- OS-level DNS configuration mutation — tracked in `net-lattice`.
- Rule-syntax compilation — tracked in `flow-lattice`.
- TUN/TAP device management — tracked in `tunnel-lattice`.
- Cross-crate composition and application wiring — tracked in `sdk-lattice`.
