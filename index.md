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

Stages 0.0 through 1.0 are complete. The 0.6 release line contains the full
pre-1.0 implementation surface: DNS model and matching, static split DNS,
resolver/cache, UDP/TCP/DoT/DoH/DoQ upstreams and inbound listeners, Fake IP,
route-selection hooks, structured observability, deterministic hardening
coverage, cross-platform feature-matrix CI, strict rustdoc gates, package
validation, and release-automation regression checks.

Stage 1.0 froze and audited the public API, established the stable SemVer
contract, verified package/docs.rs behavior, and published `dns-lattice`,
`dns-lattice-core`, and `dns-lattice-model` as `1.0.0` on crates.io. Within
the `1.x` line, ordinary SemVer now applies: additive changes are minor
releases, fixes are patch releases, and a breaking change requires an
explicit major version bump.

See `CONTRIBUTING.md` and `SUPPORT.md` for contributor and support guidance.

## Useful commands

```text
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
git diff --check
```
