# Git rules

`config.toml` currently sets no `approval_policy`/`sandbox_mode`, so none of
these destructive-command restrictions are mechanically enforced for Codex
the way `.claude/settings.json`'s `permissions.deny` enforces them for
Claude Code — these remain instructions the agent must follow deliberately.

- Inspect `git status --short` and `git diff --check` before and after each
  bounded task.
- Preserve unrelated user changes; never use `git reset --hard`, `git
  clean`, or broad checkout commands.
- Do not amend, rebase, force-push, or create commits unless the user asks
  for a specific Git operation.
- Every commit MUST name the `DL-*` issue ID(s) it relates to, AND MUST use
  this exact subject-line format:

  ```text
  <type>/DL-<id>: <summary>
  ```

  `<type>` is a standard Conventional Commits type (`feat`, `fix`, `docs`,
  `refactor`, `chore`, `perf`, `test`, `ci`, `build`) chosen for what the
  commit actually does. `<id>` is the primary `DL-*` issue this commit
  implements (e.g. `feat/DL-20: add UDP upstream backend`). If one commit
  spans more than one Task, use the primary Task's ID in the subject and
  mention every other relevant `DL-*` ID in the body. A breaking change uses
  the type's own `!` marker (e.g. `feat!/DL-20: ...`). Do not use YouTrack
  command keywords (e.g. `fixes DL-13`) that could auto-transition `Stage`
  — Stage transitions are role-gated and must stay explicit API calls.
  - Commits made before this rule was codified (2026-08-11, the YouTrack
    migration) may not follow this format; do not amend/rewrite them
    retroactively — apply the format going forward only.
- If the change implements or follows a decision recorded in a YouTrack
  Article (an ADR under `DL-A-1`, e.g. `DL-A-7`), also name that Article ID
  in the commit message alongside the issue ID(s).
- Keep patches narrow and reviewable. Separate model/API, backend, tests,
  and documentation changes when practical.
- `.codex/`, `.claude/`, root `AGENTS.md`, `CLAUDE.md`, and `index.md` may
  be intentionally local agent context (none are gitignored — they are
  tracked but govern agent workflow, not crate content); inspect them but
  never force-add them. Do not change ignore policy unless the user
  explicitly asks.
- Before handoff, report changed tracked files, verification commands, and
  any privileged/platform-specific tests not run locally.
