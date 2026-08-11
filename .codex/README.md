# DNS Lattice Codex configuration

This directory contains reusable repository workflow, not the state of one
roadmap stage. Task-specific plans, evidence, and decisions live in the
YouTrack project `DL` (https://hush.youtrack.cloud/projects/DL).

## Load order

1. Read root `AGENTS.md` and `index.md`.
2. Identify the active Epic (roadmap stage) and Task/Story in the `DL`
   YouTrack project; read its description, prior comments, and any linked
   ADR Articles under `DL-A-1` before editing anything.
3. Load all six rule files in `rules/` (`ci.md`, `files.md`, `git.md`,
   `research.md`, `versioning.md`, `youtrack.md`). Codex has no glob/
   conditional or per-role rule loading in `config.toml`, so read the full
   set every session and apply judgment about which constraints bind the
   current slice.
4. When acting as `researcher`, `architect`, `implementer`, or `reviewer`
   (`agents/*.md`), that file narrows which of the already-loaded rules are
   load-bearing for the role. Post an explicit "not applicable" comment
   when a mechanical slice does not need architecture work.
5. Let the primary agent reconcile every handoff with the active Task/Story
   and record the result as a YouTrack comment.

Codex has no native YouTrack MCP integration configured in `config.toml`;
`rules/youtrack.md` documents the REST-API fallback (`curl` with a bearer
token). `config.toml` also sets no `approval_policy`/`sandbox_mode`, so
nothing in `rules/git.md` is mechanically enforced for Codex the way the
equivalent Claude Code rules are via `permissions.deny` in
`.claude/settings.json` — these remain instructions the agent must follow
deliberately, not a tool-level block.

## Relationship to `.claude/`

`.claude/` is the equivalent workflow for Claude Code sessions, entered via
root `CLAUDE.md`. The two directories are independent at runtime — Codex
reads only `.codex/` and never `.claude/` — but they are kept in sync by
convention: when a rule or role changes in one, mirror the change into the
other so both agents follow the same policy.

## Contents

- `config.toml` — minimal repository-local Codex discovery settings.
- `rules/` — reusable YouTrack, file, Git, research, CI, and versioning
  constraints.
- `agents/` — role profiles for research, design, implementation, and review.
- `templates/` — request-body references for creating YouTrack Epics
  (`epic.md`), Stories (`story.md`), Tasks/Bugs (`task.md`), and ADR
  Articles (`adr-article.md`).

## Starting a new stage or task

Follow `templates/epic.md` → `templates/story.md` → `templates/task.md` to
create the Epic/Story/Task hierarchy directly in the `DL` YouTrack project.
Do not create a `.ai/<task-name>/` directory — that workflow is retired;
see `rules/youtrack.md` for the full field/hierarchy contract.

## Handoff contract

Every role posts a YouTrack comment containing its role, the Task/Story it
worked, files/symbols inspected, output, commands, unresolved risks, and
next role. The reviewer must not reuse the implementer's claim as evidence:
it inspects the diff and verification results independently.
