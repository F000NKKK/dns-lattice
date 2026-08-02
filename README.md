# DNS Lattice

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

## Status

**Pre-release.** Repository workflow, policies, and packaging scaffolding
were ported from [net-lattice](https://github.com/F000NKKK/net-lattice),
the first crate in the Lattice networking ecosystem. Stage 0.1 (core
model) has landed the DNS message, zone/domain matcher, and split-DNS
policy model. `0.1.0` versions of the three crates below were published to
reserve their names on crates.io; no public API is stable yet, and the
facade crate's version increments once per completed roadmap stage.

## Workspace crates

The workspace is split into focused crates, mirroring `net-lattice`'s
topology. Each crate has its own crate-level README with its scope and a
usage example:

| Crate | Purpose |
| --- | --- |
| [`dns-lattice`](crates/dns-lattice/README.md) | Public facade: re-exports the crates below as the crate's stable surface |
| [`dns-lattice-model`](crates/dns-lattice-model/README.md) | DNS message, zone/domain matcher, and split-DNS policy model |
| [`dns-lattice-core`](crates/dns-lattice-core/README.md) | Shared `Error`/`Result` types |

See `ROADMAP.md` for what each later stage (server, resolver engine,
upstream transports, Fake IP, dynamic routing hooks) is expected to add.

## The Lattice ecosystem

| Crate | Purpose |
| --- | --- |
| [net-lattice](https://github.com/F000NKKK/net-lattice) | OS networking inspection and configuration (routes, DNS, interfaces) |
| [tunnel-lattice](https://github.com/F000NKKK/tunnel-lattice) | TUN/TAP tunnel interfaces |
| [dns-lattice](https://github.com/F000NKKK/dns-lattice) | Programmable DNS control plane |
| [flow-lattice](https://github.com/F000NKKK/flow-lattice) | Policy compiler: rules -> platform-neutral network plans |
| [sdk-lattice](https://github.com/F000NKKK/sdk-lattice) | Application-facing SDK composing the crates above |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feedback on scope and API direction is
the most valuable contribution at this stage.

## License

Licensed under the [Mozilla Public License 2.0](LICENSE).
