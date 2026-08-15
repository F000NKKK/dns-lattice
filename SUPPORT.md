# Support

Thank you for your interest in DNS Lattice.

## Getting Help

- **Questions and discussion:** Use [GitHub Discussions](https://github.com/F000NKKK/dns-lattice/discussions) for general questions, ideas, and design discussion.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/F000NKKK/dns-lattice/issues) with the appropriate issue template.
- **Security issues:** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Do not report security issues via public issues or discussions.

## Project Status

DNS Lattice remains pre-1.0. Stages 0.1-0.3 delivered the DNS
message/matcher/policy model, resolver/cache, upstream transports, failover,
and inbound server listeners. Stage 0.4 added opt-in Fake IP synthesis,
TTL-bound mappings, and caller-owned process-local snapshots. Stage 0.5 added
the dynamic route-selection hook pipeline: it selects an existing upstream
group before route-scoped cache lookup, has no OS/network side-effect
authority, and does not silently fall back after hook failures or invalid
selections.

Stage 0.6 is complete and defines the `0.6.0` hardening release: the public
surface now has Linux/Windows/macOS feature-matrix validation, deterministic
parser/matcher/cache/Fake-IP invariant coverage, structured non-authoritative
resolver observability, strict per-feature rustdoc gates, package-content
checks, and release-automation regression coverage. The remaining 0.6 release
operation is the repository's mechanical version bump/publication step; there
is no remaining stage-0.6 implementation work.

The next development milestone is stage 1.0: freeze and audit the public API,
record the stable SemVer commitment, verify final package/docs.rs behavior,
and publish the first stable release. Until 1.0 ships, the public API is still
allowed to evolve. Durable Fake IP persistence remains outside the current
crate scope. Questions, bug reports, and design discussion are welcome.
