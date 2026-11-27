# DNS Lattice project index

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

This repository has reached its stable `1.x` release line: repository
workflow, policies, packaging, the DNS model, resolver/cache, upstream
transports, inbound listeners, Fake IP, dynamic routing hooks, the stage-0.6
hardening surface, and the stage-1.0 public-API freeze are all implemented.
See `CHANGELOG.md` for the current published version. `ARCHITECTURE.md` /
`ARCHITECTURE.ru.md` record the design and `ROADMAP.md` / `ROADMAP.ru.md`
sequence the delivery stages; read both before starting or continuing work.
Task-specific plans, evidence, and decisions live in the YouTrack project
`DL` (https://hush.youtrack.cloud/projects/DL), reached via the
`mcp__youtrack__*` tools (Claude Code) or the YouTrack REST API (Codex) — this
replaced the former file-based `.ai/<task-name>/` workspace on 2026-08-11.

## Workspace map

```text
dns-lattice/
├── crates/
│   ├── dns-lattice/                Facade crate: re-exports the public surface
│   ├── dns-lattice-core/           Shared Error/Result (no OS or networking types)
│   └── dns-lattice-model/          DNS message, matcher, and policy model
├── .github/workflows/          CI
├── .codex/                     Reusable Codex rules, roles, and templates
├── .claude/                    Reusable Claude Code rules, roles, and templates
├── ARCHITECTURE.md             Architecture (English)
├── ARCHITECTURE.ru.md          Architecture (Russian)
├── ROADMAP.md                  Stage sequencing (English)
├── ROADMAP.ru.md               Stage sequencing (Russian)
├── README.md                   English user documentation
├── README.ru.md                Russian user documentation
├── CHANGELOG.md                Release history
├── SECURITY.md                 Vulnerability reporting policy
├── SUPPORT.md                  Support and project status
├── CONTRIBUTING.md             Contribution workflow
├── AGENTS.md                   Repository agent entry point (Codex)
├── CLAUDE.md                   Repository agent entry point (Claude Code)
└── index.md                    This project map
```

## Lattice ecosystem

DNS Lattice is one crate in the Lattice networking ecosystem:

```text
net-lattice      OS networking inspection/configuration (routes, DNS, interfaces)
tunnel-lattice   TUN/TAP tunnel interfaces
dns-lattice      Programmable DNS control plane
flow-lattice     Policy compiler: rules -> platform-neutral network plans
sdk-lattice      Application-facing SDK composing the crates above
```

Cross-crate dependency direction and API boundaries are recorded in
`ARCHITECTURE.md`; cross-crate decisions are further tracked as ADRs once
implementation starts.

## Current status

The three crates are published at `1.2.0`. They provide the DNS model,
resolver and cache, built-in UDP/TCP/DoT/DoH/DoQ transports and listeners,
Fake IP, routing hooks and observability. Built-in network I/O currently
requires Tokio; DNSSEC validation and a choice of TLS crypto provider are
not yet implemented. Executor independence, DNSSEC and provider selection
are current work. Breaking public API changes require a major release.

See `CONTRIBUTING.md` and `SUPPORT.md` for contributor and support guidance.

## Useful commands

```text
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
git diff --check
```
