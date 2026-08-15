# Release and versioning rules

- One roadmap Sprint maps to one release version. Sprint `0.3` ships as
  crate version `0.3.x`, Sprint `0.4` ships as `0.4.x`, and so on. The
  YouTrack `Sprint DL` custom field and the crates' SemVer minor version
  march together pre-1.0 — do not invent a different mapping when filing or
  scoping issues. The historical `Sprint DL: 0.1` import (stages 0.0-0.2,
  see `DL-2`) predates per-stage Sprint tracking and does not itself imply a
  `0.1.x` release line beyond what already shipped.
- Stages through 0.6 are complete. Stage 0.6 maps to the `0.6.x` release line
  and is the final pre-1.0 implementation/hardening milestone in the current
  roadmap. Stage 1.0 is next and establishes the first stable public API and
  stable SemVer contract.
- Before 1.0, a Sprint's release is allowed to change the public API
  meaningfully — add, remove, or reshape public types/traits/methods — as
  normal roadmap evolution, provided the change is recorded in an ADR (see
  `@.claude/rules/youtrack.md`) and in `CHANGELOG.md`. Do not treat a pre-1.0
  minor bump as a compatibility guarantee, and do not block a design on
  preserving a pre-1.0 import path purely for compatibility's sake.
- Once a crate reaches `1.0.0`, ordinary SemVer discipline applies within a
  major version (`1.x`, `2.x`, ...): additive public API belongs in minor
  releases, compatible fixes in patch releases, and breaking public-contract
  changes require an explicitly user-authorized major-version bump.
- `Cargo.toml` version numbers are set by the user or by the repository release
  script explicitly invoked by the user. Agents never choose or edit a crate's
  `version` field ad hoc. If a public API change plausibly warrants a bump,
  flag the version-consistency question in the active issue instead of
  guessing.
- When a crate's version changes, review `CHANGELOG.md`, `SECURITY.md`,
  `SUPPORT.md`, root/crate READMEs, and both roadmap languages together per
  `@.claude/rules/files.md`.
- A completed stage must not remain described as `active`, `under development`,
  or future work in public documentation. Release preparation is distinct from
  implementation status: a stage may be `done` while the mechanical Cargo
  version bump/publication is still pending.
