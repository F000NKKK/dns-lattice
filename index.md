# DNS Lattice project index

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

This repository is in the bootstrap stage: base repository workflow,
policies, and packaging are in place, but the crate(s) below are placeholders
with no implementation yet. `ARCHITECTURE.md` / `ARCHITECTURE.ru.md` record
the target design and `ROADMAP.md` / `ROADMAP.ru.md` sequence the stages
that implement it; read both before starting or continuing any stage.

## Workspace map

```text
dns-lattice/
├── crates/
│   └── dns-lattice/                Placeholder crate, no implementation yet
├── .ai/<task-name>/            Ignored task plans, audits, and ADRs
├── .github/workflows/          CI
├── .codex/                     Reusable Codex rules, roles, and templates
├── ARCHITECTURE.md             Target architecture (English)
├── ARCHITECTURE.ru.md          Target architecture (Russian)
├── ROADMAP.md                  Stage sequencing (English)
├── ROADMAP.ru.md                Stage sequencing (Russian)
├── README.md                   English user documentation
├── README.ru.md                Russian user documentation
├── CHANGELOG.md                Release history
├── SECURITY.md                 Vulnerability reporting policy
├── SUPPORT.md                  Support and project status
├── CONTRIBUTING.md             Contribution workflow
├── AGENTS.md                   Repository agent entry point
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

No release has been published yet. `ROADMAP.md` tracks stage 0.0 (audit,
roadmap, architecture baseline) as active; see `CONTRIBUTING.md` and
`SUPPORT.md` for current project status language.

## Useful commands

```text
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
git diff --check
```
