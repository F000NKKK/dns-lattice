# Security Policy

## Supported Versions

DNS Lattice's crates (`dns-lattice`, `dns-lattice-model`, `dns-lattice-core`)
published `0.4.0`. Development on `main` has completed stages 0.1-0.4; no
public API is stable yet. Security fixes target the latest `0.4.x` release and
the development state on `main`.

| Version | Supported |
| ------- | --------- |
| 0.4.x   | ✅ |

## Reporting a Vulnerability

If you discover a security vulnerability in DNS Lattice, please **do not** open a
public GitHub issue.

Instead, report it privately using
[GitHub's private vulnerability reporting](https://github.com/F000NKKK/dns-lattice/security/advisories/new)
feature for this repository.

Please include as much of the following information as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected versions or commits, if known
- Any suggested mitigations

We will make a best effort to acknowledge reports promptly and to keep you
informed as the issue is investigated and resolved.

## Scope

The latest published `0.4.0` release provides a hand-rolled DNS message model
(`dns-lattice-model`'s `message`/`record` modules: header, question, and
resource-record wire encode/decode, including name decompression on
decode), a deterministic zone/domain matcher (`matcher`), and static
split-DNS policy types (`policy`) — all pure, in-memory, no network I/O.
`dns-lattice-core` provides the shared `Error`/`Result` pair. The published
`dns-lattice` facade also provides the resolver/cache, UDP/TCP/DoT/DoH/DoQ
upstream transports, matching inbound listeners, and the opt-in Fake IP
resolver behavior and pool described below.

Reports involving a decode panic, an infinite loop or excessive resource
consumption on malformed wire input (e.g. a crafted name-compression
pointer loop), incorrect matcher precedence that could cause a query to be
misrouted, cache poisoning or unbounded resource consumption, transport or
TLS/QUIC failures that violate the documented error boundary, malformed DoH
request handling, and listener failures are in scope. Reports of incorrect
allocation, reverse lookup, or unbounded resource consumption in the
development-state Fake IP pool, policy matching, local IN A/AAAA and
canonical in-range IN PTR synthesis, or their TTL/expiry handling are also in
scope. Dynamic routing hooks are not implemented yet and remain out of scope
until their corresponding stage ships.
