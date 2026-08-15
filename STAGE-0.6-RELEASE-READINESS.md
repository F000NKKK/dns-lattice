# DNS Lattice stage 0.6 release readiness

Date: 2026-08-15
Baseline commit: `bcc751b1eca45439d64335d174bc293aa6def0ce`
GitHub Actions run: `31821041466` (`CI`, `main`)

## Result

Stage 0.6 implementation and external cross-platform verification are complete.
The repository is release-ready from the implementation/CI side.

The only intentionally unresolved release action is the crate version change and
publication. Repository policy in `.codex/rules/versioning.md` requires the
version number to be chosen by the user rather than by an agent.

## Verified gates

The `main` CI run for the baseline commit completed successfully.

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

## Stage 0.6 implementation already present on main

- Cross-platform CI and strict per-feature rustdoc validation.
- Deterministic property-style coverage for DNS parsing/compression bounds,
  matcher precedence, resolver cache identity, and Fake IP TTL/LRU invariants.
- Opt-in `observability::ObservabilitySink` with bounded immutable events and no
  authority over resolver behavior.
- Package-content and release-automation hardening.

## Remaining release actions

1. User selects the stage 0.6 crate version in accordance with repository
   versioning policy (the expected roadmap line is `0.6.x`; the exact version is
   deliberately not chosen in this document).
2. Apply the version bump consistently to all workspace crates and workspace
   dependency versions.
3. Reconcile `CHANGELOG.md`, `SECURITY.md`, `SUPPORT.md`, root/crate READMEs,
   and EN/RU roadmap status with the selected release version.
4. Run the release preflight from `scripts/release.sh`.
5. Publish crates in dependency order and create the corresponding GitHub
   release/tag using the repository release automation.
6. Confirm crates.io and docs.rs publication, then mark stage 0.6 fully
   published and activate stage 1.0.

No implementation defect or failed platform gate is currently known to block
stage 0.6.