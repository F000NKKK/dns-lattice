# Git rules

The destructive-command restrictions below are also enforced mechanically
via `permissions.deny` in `.claude/settings.json`, not just as prose here.

- Inspect `git status --short` and `git diff --check` before and after each
  bounded task.
- Preserve unrelated user changes; never use `git reset --hard`, `git
  clean`, or broad checkout commands.
- Do not amend, rebase, force-push, or create commits unless the user asks
  for a specific Git operation.
- Every commit MUST name the `DL-*` issue ID(s) it relates to, AND MUST use
  this exact subject-line format so both Conventional-Commits-based release
  tooling and any future release-search script that groups commits by `DL-*`
  ID can parse it:

  ```text
  <type>/DL-<id>: <summary>
  ```

  `<type>` is a standard Conventional Commits type (`feat`, `fix`, `docs`,
  `refactor`, `chore`, `perf`, `test`, `ci`, `build`) chosen for what the
  commit actually does — do not default to `feat` for a docs-only or
  refactor-only change. `<id>` is the primary `DL-*` issue this commit
  implements (e.g. `feat/DL-20: add UDP upstream backend`). If one commit
  spans more than one Task, use the primary Task's ID in the subject and
  mention every other relevant `DL-*` ID in the body. A breaking change
  still uses the type's own `!` marker before the slash if the project's
  Conventional Commits convention calls for one (e.g. `feat!/DL-20: ...`).
  This is mandatory on every commit, not optional polish: it is how a diff
  traces back to its authorizing Task/Story/Epic/Bug, and the GitHub
  repository is expected to be linked to YouTrack's VCS integration so a
  referenced ID also auto-links the commit to that issue's activity feed.
  Do not use YouTrack command keywords (e.g. `fixes DL-13`, `closes DL-13`)
  that could auto-transition the issue's `Stage` — Stage transitions in this
  workflow are role-gated (reviewer confirmation required before `Done`, see
  `@.claude/rules/youtrack.md`) and must stay explicit
  `mcp__youtrack__update_issue` calls, not a side effect of a commit
  message.
  - Commits made before this rule was codified (2026-08-11, the YouTrack
    migration) may not follow this format; do not amend/rewrite them
    retroactively (that requires explicit user authorization per the
    destructive-operation restrictions above) — apply the format going
    forward only.
- If the change implements or follows a decision recorded in a YouTrack
  knowledge-base Article (an ADR under `DL-A-1`, e.g. `DL-A-7`), also name
  that Article ID in the commit message alongside the issue ID(s) — a diff
  that exists because of an ADR must be traceable back to it from the
  commit, not only from the issue description.
- Keep patches narrow and reviewable. Separate model/API, backend, tests,
  and documentation changes when practical.
- `.codex/`, `.claude/`, root `AGENTS.md`, `CLAUDE.md`, and `index.md` may be
  intentionally local agent context (none of them are gitignored — they are
  tracked but govern agent workflow, not crate content); inspect them but
  never force-add them. Do not change ignore policy unless the user
  explicitly asks.
- Before handoff, report changed tracked files, verification commands, and
  any privileged/platform-specific tests not run locally.
