# Research and tool-use rules

- Prefer targeted reads and repository search over broad scans.
- Use `cargo metadata --no-deps --format-version 1` to inspect package
  relationships and `cargo package -p <crate> --allow-dirty --list` to
  verify published file contents.
- Use `git diff`, `git log`, and `git status` as evidence, not as a
  substitute for reading source and tests.
- Check prior evidence recorded as comments on the active Epic/Story/Task
  before re-deriving it; see `rules/youtrack.md`.
- Inspect every relevant implementation (module and, once they exist,
  platform-specific backend) before claiming parity or completeness.
- Separate compile-time provider/trait contracts, runtime feature gating
  (Cargo features for DoT/DoH/DoQ), native privilege requirements, and
  eventual event delivery in findings.
- Cite exact paths and symbols in audit reports; avoid unsupported
  assumptions.
- Prefer repository and primary-source evidence. If a current external fact
  is material, use the appropriate authoritative source and record its URL
  and access date rather than guessing.
