# Test and CI rules

- Ordinary tests must be deterministic, non-privileged, and non-destructive
  — no real network I/O, no real `sleep` (use a fake/injectable clock, see
  `DL-A-10`'s `Clock` abstraction as the established pattern).
- Test Linux, Windows, and macOS behavior separately once platform-specific
  backend code exists; a passing Linux test does not establish platform
  parity. DNS Lattice's core is cross-platform by design, so most tests
  should already be fully portable.
- Derive the behavior matrix from the active YouTrack Task/Story. Normally
  cover success, invalid input, missing/no-route cases, capability/feature
  gating (e.g. DoT/DoH/DoQ behind Cargo features), transport failure,
  partial application, cache hit/miss/expiry, and cancellation where
  applicable.
- Run formatting, workspace tests, clippy, docs, package listing, and diff
  checks before advancing a YouTrack Task's `Stage` field to `Done`.
- Run package listings for every crate whose manifest, README, features, or
  public dependencies changed; verify the archive contains its local README.
- Never relax coverage or lint policy as a substitute for missing behavior;
  add focused tests or document a deliberate platform/feature limitation.
