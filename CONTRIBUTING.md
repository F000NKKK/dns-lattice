# Contributing to DNS Lattice

Thank you for your interest in contributing to DNS Lattice.

## Project Status

DNS Lattice is pre-release: repository workflow, policies, and packaging
scaffolding are in place, ported from
[net-lattice](https://github.com/F000NKKK/net-lattice), and the DNS
message/matcher/policy model, resolver/cache, upstream transports, failover,
and inbound server listeners (stages 0.1-0.3) have landed in published
releases. Published `0.5.0` adds opt-in resolver/server Fake IP synthesis and
caller-owned process-local mapping snapshots. Development on `main` has
completed and published the stage 0.5 route-selection hook pipeline: selection
is before route-scoped caching, while
timeout/retry/cancellation cleanup and external side effects stay in the hook
implementation or composing application. Work on `main` is now stage 0.6
hardening and platform validation. No public API is stable yet. The
most valuable contributions right now are:

- Feedback on the project's vision, scope, and roadmap (see [README.md](README.md))
- Discussion of API design and architecture for planned stages
- Documentation and tooling improvements

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
