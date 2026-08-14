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

Status: done

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

Status: done

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

Status: done

- `upstream` backend trait stabilized (from `ARCHITECTURE.md`). Done.
- UDP and TCP upstream backends (baseline, no TLS/QUIC dependency). Done.
- DoT and DoH upstream backends behind explicit Cargo features. Done.
- DoQ upstream backend behind an explicit Cargo feature, if a maintained
  QUIC/HTTP-3 dependency is available for all target platforms; otherwise
  record the gap as an ADR and defer. Done — `quinn` cleared the bar; the
  `doq` Cargo feature landed (`DoqBackend`/`DoqBackendConfig`).
- Fallback/failover across upstreams within a group (see the failure-flow
  diagram in `ARCHITECTURE.md`). Done.
- `server` inbound listener: UDP and TCP first, matching the crate's
  Kestrel-style embeddable-server goal from `ARCHITECTURE.md`; DoT/DoH/DoQ
  listeners behind the same Cargo features as their upstream counterparts.
  UDP/TCP baseline done (`Server`/`ServerBuilder`); DoT listener done
  (`ServerBuilder::dot_addr`, `dot` Cargo feature); DoQ listener done
  (`ServerBuilder::doq_addr`, `doq` Cargo feature); DoH listeners done:
  TCP `ServerBuilder::doh_addr` supports ALPN-negotiated HTTP/1.1 and HTTP/2
  over TLS 1.2/1.3, while QUIC `ServerBuilder::doh3_addr` supports HTTP/3
  with ALPN `h3` and TLS 1.3 (`doh` Cargo feature). Final cross-platform
  verification passed.
- Non-goal: no platform-specific privileged transport (e.g. raw sockets,
  binding privileged ports) — that stays the composing application's
  responsibility, typically via `net-lattice`.

## Stage 0.4 — Fake IP

Status: completed and published in 0.4.0

- Implemented: deterministic allocation of synthetic IPv4/IPv6 addresses per
  domain, reverse lookup (address -> domain), explicit not-found handling,
  per-family LRU eviction on pool exhaustion, TTL expiry, and caller-owned
  in-memory snapshot/restore of live mappings.
- `FakeIpPolicy` plus `ResolverBuilder::fake_ip` explicitly enable local
  behavior: matching IN A/AAAA queries synthesize an address, while canonical
  in-range IN PTR queries return the live name or NXDOMAIN. These local
  answers bypass the ordinary cache/upstreams and advertise no more than the
  mapping's remaining lifetime.
- Snapshot/restore remains caller-owned, process-local in-memory state; this
  crate supplies no serialization or durable persistence. DNS Lattice has no
  direct dependency on `tunnel-lattice`; composition belongs above this crate.
- Release validation, package reconciliation, and independent review completed
  before publication.

## Stage 0.5 — Dynamic routing hooks

Status: done; published in 0.5.0

- Implemented on `main`: `hooks::RouteHook` lets a caller (e.g.
  `flow-lattice`) select one existing upstream group per ordinary query
  without a compile-time dependency from `dns-lattice` on that caller.
- Explicit resolver precedence: terminal Fake IP local synthesis, static
  split-DNS candidate, optional hook `Use`/`Abstain`, selected-group
  validation, route-scoped cache, then ordered upstream failover. Hook errors
  and invalid selected groups do not silently fall back.
- The hook is intentionally one-at-a-time and selection-only: no multiple
  hook composition, response rewrite, cache-policy override, resolver
  re-entry, or OS/network side effect is in scope. Hook implementations own
  timeout, retry, and cancellation cleanup.
- Stage verification, public documentation/package reconciliation, independent
  review, and release validation are complete.

## Stage 0.6 — Hardening and platform validation

Status: active

- Implemented on `main`: Linux/Windows/macOS CI exercises every supported
  feature selection with strict per-feature rustdoc checks; package contents
  and release-automation regression are also checked hermetically.
- Implemented on `main`: deterministic property-style coverage for message
  parsing/compression bounds, matcher precedence, resolver cache identity,
  and Fake IP expiry/eviction invariants.
- Implemented on `main`: opt-in `observability::ObservabilitySink` emits
  immutable, bounded query/cache/route/hook/upstream/terminal events without
  client data, handles, or authority over resolution.
- Remaining: external cross-platform CI confirmation and final release/docs
  reconciliation; no stage 0.6 release has been published.
- Keep English/Russian rustdoc, crate READMEs, root docs, CHANGELOG, SECURITY,
  SUPPORT, and CONTRIBUTING synchronized as each hardening contract lands.

## Stage 1.0 — Stable public API and first stable release

Status: planned

- Public API frozen; SemVer commitment recorded.
- `cargo package` verified for the crate; docs.rs build verified.
- First stable release on crates.io.

## Explicitly out of scope for this crate's roadmap

- OS-level DNS configuration mutation — tracked in `net-lattice`.
- Rule-syntax compilation — tracked in `flow-lattice`.
- TUN/TAP device management and packet forwarding.
- Cross-crate composition and application wiring — tracked in `sdk-lattice`.
