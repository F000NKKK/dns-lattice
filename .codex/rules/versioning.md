# Release and versioning rules

- One roadmap Sprint maps to one release version. Sprint `0.3` ships as
  crate version `0.3.x`, Sprint `0.4` ships as `0.4.x`, and so on. The
  YouTrack `Sprint DL` custom field and the crates' SemVer minor version
  march together pre-1.0. The historical `Sprint DL: 0.1` import (stages
  0.0-0.2, `DL-2`) predates per-stage Sprint tracking and does not itself
  imply a `0.1.x` release line beyond what already shipped.
- DNS Lattice is pre-1.0 (`ROADMAP.md` gates 1.0 behind the stage 1.0
  milestone; crates through 0.4.0 are published, while 1.0 is the first
  stable release). Before 1.0, a Sprint's
  release is allowed to change the public API meaningfully as normal
  roadmap evolution, provided the change is recorded in an ADR (see
  `rules/youtrack.md`) and in `CHANGELOG.md`. Do not treat a pre-1.0 minor
  bump as a compatibility guarantee.
- Once a crate reaches `1.0.0`, ordinary SemVer discipline applies within a
  major version — nothing already public may be removed or changed without
  a major version bump, and that bump is an explicit, user-authorized
  decision, not something folded into a routine Sprint release.
- `Cargo.toml` version numbers are set by the user, not by an agent. If a
  crate gained public API that plausibly warrants a version bump, flag that
  question in the relevant issue's evidence comment instead of guessing.
- When a crate's version does change, `CHANGELOG.md`, `SECURITY.md`'s
  supported-version table, and `SUPPORT.md`'s project-status summary must be
  reviewed together per `rules/files.md`.
