# dns-lattice-model

The DNS message, zone/domain matcher, and policy model for DNS Lattice. No
network I/O, no operating-system dependency.

## What it provides

- `message`: a hand-rolled DNS message model (`Header`, `Question`,
  `ResourceRecord`, `Message`) with wire encode/decode.
- `record`: DNS record types and resource-data (`RecordType`, `Class`,
  `RData`).
- `matcher`: a zone/domain matcher (`DomainPattern`, `DomainMatcher<T>`)
  with deterministic exact/suffix/wildcard precedence.
- `policy`: split-DNS policy types (`UpstreamGroupId`, `SplitDnsPolicy`)
  built on the matcher.

Most applications should use these types through the `dns-lattice` facade
crate rather than depending on this crate directly. Depend on it directly
when implementing a component that needs the DNS model without the rest of
`dns-lattice`.

Stage-0.6 hardening added deterministic property-style verification around
message parsing/compression bounds and matcher precedence without introducing
network or OS responsibilities into this crate.

## Status

**Stable `1.x` releases are published** on crates.io. The public model is
frozen; ordinary SemVer guarantees apply within the `1.x` line — a breaking
change requires an explicit major version bump.
