# Contributing to DNS Lattice

Thank you for your interest in contributing to DNS Lattice.

## Project Status

DNS Lattice reached its first stable release, `1.0.0` (`dns-lattice`,
`dns-lattice-core`, `dns-lattice-model` on crates.io). The repository
contains the DNS message/matcher/policy model, resolver/cache,
UDP/TCP/DoT/DoH/DoQ upstream transports, failover, matching inbound server
listeners, Fake IP synthesis and snapshots, dynamic route-selection hooks,
structured observability, deterministic hardening coverage, cross-platform
feature-matrix CI, strict per-feature rustdoc checks, package validation, and
release-automation regression coverage.

The public API is now frozen: within the `1.x` line, ordinary SemVer applies
— additive changes land as minor releases, fixes as patch releases, and a
breaking change requires an explicit major version bump.

The most valuable contributions now are:

- documentation, examples, and docs.rs polish;
- ergonomics review that stays within the frozen `1.x` compatibility
  contract;
- package/release reproducibility and cross-platform validation improvements;
- focused bug fixes with deterministic regression coverage;
- design discussion for new capability domains beyond the current 1.0 scope.

Please check open issues and discussions before starting significant work, to
avoid duplicated effort.

## Getting Started

1. Fork the repository and clone your fork.
2. Create a topic branch for your change.
3. Make your changes, following the conventions described below.
4. Open a pull request against `main` using the provided pull request template.

## Development Conventions

DNS Lattice follows standard Rust ecosystem conventions:

- Code must be formatted with `rustfmt`.
- Code must be free of `clippy` warnings.
- Public APIs must be documented.
- Changes must include appropriate tests.
- CI treats `cargo doc --no-deps` with warnings denied across every supported
  feature selection as the local docs.rs-compatible documentation gate; it
  does not publish or query docs.rs during pull-request validation.
- CI lists reproducible `cargo package --workspace --allow-dirty` archives and
  runs the hermetic release-automation regression script. These checks never
  publish a crate, create a tag, or contact GitHub/crates.io.
- Every affected crate must retain a standalone crate-local README, and
  English/Russian project documentation must remain synchronized.
- Privileged network tests must be isolated, opt-in, and restore changed state.
- Commit messages should be clear and descriptive.

## Reporting Issues

Please use the issue templates under `.github/ISSUE_TEMPLATE/` when filing
bug reports or feature requests. Include as much context as possible.

## Security Issues

Do not report security vulnerabilities through public GitHub issues. See
[SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Code of Conduct

By participating in this project, you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to DNS Lattice, you agree that your contributions will be licensed
under the [Mozilla Public License 2.0](LICENSE).
