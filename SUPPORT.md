# Support

Thank you for your interest in DNS Lattice.

## Getting Help

- **Questions and discussion:** Use [GitHub Discussions](https://github.com/F000NKKK/dns-lattice/discussions) for general questions, ideas, and design discussion.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/F000NKKK/dns-lattice/issues) with the appropriate issue template.
- **Security issues:** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Do not report security issues via public issues or discussions.

## Project Status

DNS Lattice reached its first stable release, `1.0.0`. Stages 0.1-0.3 delivered the DNS
message/matcher/policy model, resolver/cache, upstream transports, failover,
and inbound server listeners. Stage 0.4 added opt-in Fake IP synthesis,
TTL-bound mappings, and caller-owned process-local snapshots. Stage 0.5 added
the dynamic route-selection hook pipeline: it selects an existing upstream
group before route-scoped cache lookup, has no OS/network side-effect
authority, and does not silently fall back after hook failures or invalid
selections.

Stage 0.6 defined the `0.6.0` hardening release: the public surface has
Linux/Windows/macOS feature-matrix validation, deterministic
parser/matcher/cache/Fake-IP invariant coverage, structured non-authoritative
resolver observability, strict per-feature rustdoc gates, package-content
checks, and release-automation regression coverage.

Stage 1.0 froze and audited the public API, established the stable SemVer
commitment, and published `dns-lattice`, `dns-lattice-core`, and
`dns-lattice-model` as `1.0.0` on crates.io. Within the `1.x` line, the public
API follows ordinary SemVer: additive changes are minor releases, fixes are
patch releases, and a breaking change requires an explicit major version
bump. Durable Fake IP persistence remains outside the current crate scope.
Questions, bug reports, and design discussion are welcome.
