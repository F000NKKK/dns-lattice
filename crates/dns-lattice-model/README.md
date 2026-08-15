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

Stage-0.6 hardening adds deterministic property-style verification around
message parsing/compression bounds and matcher precedence without introducing
network or OS responsibilities into this crate.

## Status

Stage 0.6 is complete and this crate is part of the `0.6.x` pre-1.0 release
line. Its public model may still evolve during the stage-1.0 API freeze and
compatibility audit; ordinary stable SemVer guarantees begin with `1.0.0`.
