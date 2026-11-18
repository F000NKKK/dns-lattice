# Code style and architecture

This describes the current code; `ARCHITECTURE.md` and `ROADMAP.md` govern
the public contracts and delivery stages.

## Boundaries

- `core` supplies shared errors; `model` owns DNS messages, matching and
  policy types. The facade contains resolver, cache, upstream, server, Fake
  IP, hooks and observability modules.
- Resolution separates Fake IP, static route selection, the optional route
  hook, group validation, group-scoped caching and ordered upstream failover.
  A route hook selects a group; it does not own the resolver or OS state.
- Transport implementations sit behind `UpstreamBackend`; encrypted
  transports are independent opt-in features. The application owns runtime,
  configuration, certificate provisioning and OS network configuration.

## Rust conventions

- Use typed models, builders and errors, with explicit validation and
  documented behavior on failures. Preserve the stable 1.x API under SemVer.
- Document public items, invariants and async or concurrency contracts in
  rustdoc; provide examples for the application-facing API.
- Inject traits at extension boundaries and test routing, cache isolation,
  transport behavior and error paths independently; use loopback integration
  fixtures when exercising actual protocols.
- Use `cargo fmt` and the CI clippy, feature-matrix, test and rustdoc gates.
