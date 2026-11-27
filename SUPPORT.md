# Support

Thank you for your interest in DNS Lattice.

## Getting Help

- **Questions and discussion:** Use [GitHub Discussions](https://github.com/F000NKKK/dns-lattice/discussions) for general questions, ideas, and design discussion.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/F000NKKK/dns-lattice/issues) with the appropriate issue template.
- **Security issues:** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Do not report security issues via public issues or discussions.

## Project Status

The published `dns-lattice`, `dns-lattice-core`, and `dns-lattice-model`
crates are at version `1.2.0`. The resolver includes caching, Fake IP,
route-selection hooks, upstream transports and inbound listeners. Built-in
network I/O currently requires Tokio, and DNSSEC validation is not yet
implemented. Within `1.x`, breaking API changes require a major version
bump. Durable Fake IP persistence remains outside the current crate scope.
Questions, bug reports, and design discussion are welcome.
