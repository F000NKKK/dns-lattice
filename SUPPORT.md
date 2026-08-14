# Support

Thank you for your interest in DNS Lattice.

## Getting Help

- **Questions and discussion:** Use [GitHub Discussions](https://github.com/F000NKKK/dns-lattice/discussions) for general questions, ideas, and design discussion.
- **Bug reports and feature requests:** Use [GitHub Issues](https://github.com/F000NKKK/dns-lattice/issues) with the appropriate issue template.
- **Security issues:** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Do not report security issues via public issues or discussions.

## Project Status

DNS Lattice `0.4.0` is published and remains pre-1.0: stages 0.1-0.3 delivered
the DNS message/matcher/policy model, resolver/cache, upstream transports,
failover, and inbound server listeners; stage 0.4 adds opt-in Fake IP
synthesis through `Resolver` and its server transports, TTL-bound mappings,
and caller-owned process-local snapshots. Development on `main` additionally
implements the stage 0.5 dynamic route-selection hook: it selects an existing
upstream group before route-scoped cache lookup and has no OS/network side
effects. Durable persistence remains future work. No public API is stable yet. Questions, bug
reports, and design discussion are welcome; full usage support will start
once a stable release ships.
