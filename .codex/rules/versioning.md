# Release and versioning rules

- One roadmap Sprint maps to one release version. Sprint `0.3` ships as
  crate version `0.3.x`, Sprint `0.4` ships as `0.4.x`, and so on. The
  YouTrack `Sprint DL` custom field and the crates' SemVer minor version
  march together pre-1.0. The historical `Sprint DL: 0.1` import (stages
  0.0-0.2, `DL-2`) predates per-stage Sprint tracking and does not itself
  imply a `0.1.x` release line beyond what already shipped.
- Stages through 0.6 are complete. Stage 0.6 maps to the `0.6.x` release line
  and is the final pre-1.0 implementation/hardening milestone in the current
  roadmap. Stage 1.0 is next and establishes the first stable public API and
  stable SemVer contract.
- Before 1.0, a Sprint's release is allowed to change the public API
  meaningfully as normal roadmap evolution, provided the change is recorded
  in an ADR (see `rules/youtrack.md`) and in `CHANGELOG.md`. Do not treat a
  pre-1.0 minor bump as a compatibility guarantee.
- Once a crate reaches `1.0.0`, ordinary SemVer discipline applies within a
  major version — nothing already public may be removed or changed without a
  major version bump, and that bump is an explicit, user-authorized decision,
  not something folded into a routine Sprint release.
- `Cargo.toml` version numbers are set by the user or by the repository release
  script invoked by the user, not chosen ad hoc by an agent. If a crate gained
  public API that plausibly warrants a version bump, flag that question in the
  relevant issue's evidence comment instead of guessing.
- When a crate's version does change, `CHANGELOG.md`, `SECURITY.md`'s
  supported-version table, `SUPPORT.md`'s project-status summary, root/crate
  READMEs, and both roadmap languages must be reviewed together per
  `rules/files.md`.
- A completed stage must not remain described as `active`, `under development`,
  or future work in public documentation. Release preparation is separate from
  implementation status: a stage may be `done` while its mechanical Cargo
  version bump/publication is still pending.
