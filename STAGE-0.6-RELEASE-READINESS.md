# DNS Lattice stage 0.6 release readiness

Date: 2026-08-15
Baseline implementation commit: `bcc751b1eca45439d64335d174bc293aa6def0ce`
Verified GitHub Actions run: `31821041466` (`CI`, `main`)
Release line: `0.6.0`

## Result

Stage 0.6 is complete. Implementation, independent cross-platform CI
verification, package/release validation, and public documentation
reconciliation are finished.

There is no remaining stage-0.6 implementation task. The remaining release
operation is mechanical: the user invokes the repository release script to
apply the `0.6.0` Cargo version bump, run release preflight, publish the
workspace crates in dependency order, and create the release/tag.

After `0.6.0` publication, stage 1.0 is the next development milestone.

## Verified gates

The final `main` CI run for the stage-0.6 implementation baseline completed
successfully.

### Full workspace CI

Passed on:

- `ubuntu-latest`
- `windows-latest`
- `macos-latest`

Each platform passed:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-features`
- `cargo test --workspace --all-features`
- `cargo doc --no-deps --workspace --all-features`

### Facade feature matrix

The `dns-lattice` facade passed `cargo check`, `cargo test`, and strict rustdoc
(`-D warnings`) on Linux, Windows, and macOS for every supported selection:

- `--no-default-features`
- `--no-default-features --features dot`
- `--no-default-features --features doh`
- `--no-default-features --features doq`
- `--all-features`

### Packaging and release automation

Passed:

- `cargo package --workspace --allow-dirty --list`
- hermetic release-automation regression

## Stage 0.6 implementation

Complete on `main`:

- cross-platform CI and strict per-feature rustdoc validation;
- deterministic property-style coverage for DNS parsing/compression bounds,
  matcher precedence, resolver cache identity, and Fake IP TTL/LRU invariants;
- opt-in `observability::ObservabilitySink` with bounded immutable events and
  no authority over resolver behavior;
- package-content and release-automation hardening.

## Documentation reconciliation

Release documentation has been reconciled for the completed 0.6 stage:

- `README.md` / `README.ru.md`;
- `ARCHITECTURE.md` / `ARCHITECTURE.ru.md`;
- `ROADMAP.md` / `ROADMAP.ru.md`;
- `CHANGELOG.md`;
- `SECURITY.md`;
- `SUPPORT.md`;
- `CONTRIBUTING.md`;
- `index.md`;
- all three crate-local README files;
- Codex/Claude versioning guidance.

The docs now consistently describe stage 0.6 as complete, the `0.6.x` line as
the hardening release boundary, and stage 1.0 as the only next development
stage. The architecture also reflects the implemented `observability` module
and the actual facade/runtime module layout rather than the older target-state
description.

## Remaining release operation

The user-owned release step is:

1. invoke `scripts/release.sh` for the stage-0.6 minor release so Cargo
   versions/workspace dependency versions move to `0.6.0`;
2. let the script run its release preflight;
3. publish the workspace crates in dependency order;
4. create/verify the corresponding tag and GitHub release;
5. confirm crates.io/docs.rs publication.

No implementation defect, documentation gap, or failed platform gate is known
to block `0.6.0` publication.
