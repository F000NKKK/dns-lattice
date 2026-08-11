# DNS Lattice agent workflow

This file is the repository entry point for Codex and collaborating agents.
Before changing anything, read:

1. `index.md` for the workspace map and dependency direction;
2. `ARCHITECTURE.md` / `ARCHITECTURE.ru.md` for the target design and
   `ROADMAP.md` / `ROADMAP.ru.md` for stage sequencing;
3. `.codex/README.md`, the applicable rules in `.codex/rules/`, and the
   selected role profile in `.codex/agents/`;
4. the active work item in the YouTrack `DL` project (DNS Lattice,
   https://hush.youtrack.cloud/projects/DL): find the relevant Epic
   (roadmap stage), its User Story/Task children, and any linked ADR
   Articles under `DL-A-1` before editing anything. This replaces the
   former `.ai/<task-name>/` file-based workspace (`plan.md`, `AUDIT.md`,
   `adr/`), which is retired — see `.codex/rules/youtrack.md`.

Every role posts its evidence as a YouTrack comment on the active issue and
writes an ADR Article before changing a public contract or reversing an
accepted decision. Never mix unrelated or future work into the active Task.

## Agent pipeline

Run every bounded task through the repository roles in this order:

```text
researcher
    ↓ evidence and contract gaps
architect
    ↓ design, diagrams, and ADRs when required
implementer
    ↓ source, tests, rustdoc, docs, and package metadata
reviewer
    ↓ independent findings and verification gate
primary agent
    ↓ YouTrack Stage reconciliation and handoff
```

1. `researcher` maps existing code, tests, platform behavior, documentation,
   and package metadata. Its evidence comment is the input to design.
2. `architect` checks cross-crate boundaries and compatibility, produces the
   smallest design, and writes proposed ADR Articles. For a purely
   mechanical change, post "architect: not applicable" with the reason.
3. `implementer` executes one bounded YouTrack Task. It may not silently
   expand scope or decide a new public contract.
4. `reviewer` performs an independent contract, platform, test, documentation,
   and packaging review. It returns findings to the implementer or clears the
   slice for completion.
5. The primary agent reconciles role outputs with the active Task/Story,
   advances `Stage`, and records the handoff.

Each handoff must identify the active YouTrack Task, files/symbols in scope,
decisions already accepted, evidence produced, unresolved risks, and the next
role. Role instructions are defined in `.codex/agents/`; no role may keep its
only record in the session transcript.

Decompose work into the applicable model, engine, server, upstream, fakeip,
hooks, facade, test, CI, documentation, and packaging slices. A task is
complete only when source, tests, rustdoc, user documentation, package
metadata, and recorded verification agree.

After every repository change, review all affected `*.md` files and their
language counterparts. Also inspect affected manifests and extensionless or
configuration files, including `Cargo.toml`, CI definitions, scripts,
`.gitignore`, `SECURITY`, and `SUPPORT` when present. Record files reviewed
as a comment on the active YouTrack issue, even when no edit was required.

Preserve unrelated user changes, use `apply_patch` for text edits, and never
use destructive Git commands. Repository-local agent files (`.codex/`,
`.claude/`, this file, `CLAUDE.md`, `index.md`) are working context; do not
force-add ignored files or change ignore policy unless the user explicitly
requests it.
