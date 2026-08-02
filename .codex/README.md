# DNS Lattice Codex configuration

This directory contains reusable repository workflow, not the state of one
roadmap stage. Task-specific plans, evidence, and decisions live under
`.ai/<task-name>/`.

## Load order

1. Read root `AGENTS.md` and `index.md`.
2. Identify the active `.ai/<task-name>/` directory.
3. Read its `plan.md`, `AUDIT.md`, and relevant ADRs.
4. Load all five rule files in `rules/` (`audit.md`, `ci.md`, `files.md`,
   `git.md`, `research.md`). Codex has no glob/conditional or per-role rule
   loading in `config.toml`, so read the full set every session and apply
   judgment about which constraints bind the current slice.
5. When acting as `researcher`, `architect`, `implementer`, or `reviewer`
   (`agents/*.md`), that file narrows which of the already-loaded rules are
   load-bearing for the role. Record an explicit `not applicable` audit
   decision when a mechanical slice does not need architecture work.
6. Let the primary agent reconcile every handoff with the plan and record the
   result in the active task workspace.

## Contents

- `config.toml` — minimal repository-local Codex discovery settings.
- `rules/` — reusable audit, file, Git, research, and CI constraints.
- `agents/` — role profiles for research, design, implementation, and review.
- `templates/` — starting structures for a new task plan, audit log, and ADR.

## New task workspace

Create `.ai/<task-name>/` from the templates. The directory must contain:

```text
.ai/<task-name>/
├── plan.md
├── AUDIT.md
└── adr/
    ├── README.md
    └── ADR-NNNN-short-title.md
```

The plan is the authoritative TODO. `AUDIT.md` records what was inspected,
changed, and verified. ADRs record decisions, alternatives, and consequences;
they do not replace public rustdoc, architecture, or user documentation.

## Handoff contract

Every role appends an audit entry containing its role, plan checkbox,
files/symbols inspected, output, commands, unresolved risks, and next role.
The reviewer must not reuse the implementer's claim as evidence: it inspects
the diff and verification results independently.
