# DNS Lattice project index

Programmable Rust DNS control plane for the Lattice networking stack: split DNS, Fake IP, address pools, and dynamic routing hooks.

This repository is past its bootstrap stage: base repository workflow,
policies, and packaging are in place, and stages 0.1/0.2 have landed the
crate's first real implementation (the DNS message/matcher/policy model and
the resolver engine with static split DNS). `ARCHITECTURE.md` /
`ARCHITECTURE.ru.md` record the target design and `ROADMAP.md` /
`ROADMAP.ru.md` sequence the stages that implement it; read both before
starting or continuing any stage. Task-specific plans, evidence, and
decisions live in the YouTrack project `DL`
(https://hush.youtrack.cloud/projects/DL), reached via the `mcp__youtrack__*`
tools (Claude Code) or the YouTrack REST API (Codex) — this replaced the
former file-based `.ai/<task-name>/` workspace on 2026-08-11.

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

Version `0.4.0` is published; the public API remains pre-1.0 and unstable.
Stages 0.0 through 0.5 are implemented on `main`. Stage 0.5's optional
`hooks::RouteHook` selects a registered upstream group for an ordinary query
after static routing and before the route-scoped cache. Fake IP remains
terminal before hooks; hook implementations own timeout, retry, cancellation
cleanup, and any external side effects. The remaining release gate is external
CI validation. See `CONTRIBUTING.md` and `SUPPORT.md` for current status.

## Useful commands

```text
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
git diff --check
```
