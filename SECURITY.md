# Security Policy

## Supported Versions

DNS Lattice's crates (`dns-lattice`, `dns-lattice-model`, `dns-lattice-core`)
use the `0.6.x` line as the supported pre-1.0 release line. Stage 0.6 is
complete; work after that release moves to the 1.0 public-API stabilization
milestone. No public API is stable until 1.0.0 ships.

| Version | Supported |
| ------- | --------- |
| 0.6.x   | ✅ |
| 0.5.x and earlier | ❌ |

Security fixes target the latest supported `0.6.x` release and the current
development state on `main` when a fix is also relevant to the upcoming 1.0
line.

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

The supported 0.6 release surface includes the hand-rolled DNS message model
(`dns-lattice-model`'s `message`/`record` modules), deterministic domain
matcher and split-DNS policy types, the shared `dns-lattice-core` error
boundary, resolver/cache, UDP/TCP/DoT/DoH/DoQ upstream transports and inbound
listeners, Fake IP allocation/reverse lookup/TTL/snapshot behavior, dynamic
route-selection hooks, and structured resolver observability.

Reports involving any of the following are in scope:

- decode panics, infinite loops, compression-pointer loops, or excessive
  resource consumption on malformed DNS wire input;
- incorrect matcher precedence or route selection that can send a query to an
  unintended upstream group;
- cache poisoning, cache identity violations, or unbounded cache/resource
  consumption;
- transport, TLS, HTTP, or QUIC behavior that violates the documented error
  boundary or request/response validation rules;
- malformed DoH/DoH3 request handling or listener failures that can crash,
  hang, or bypass the resolver policy;
- Fake IP allocation, eviction, reverse lookup, snapshot restoration, or
  TTL/expiry behavior that can corrupt mappings or consume resources without
  bound;
- route-hook behavior that leaks a query through unintended static fallback,
  shares cache entries across effective groups, bypasses terminal Fake IP
  handling, fails cancellation isolation, or enables same-resolver re-entry;
- observability sink behavior that can mutate resolver authority/state, escape
  its documented panic isolation, or unexpectedly retain privileged runtime
  handles/client transport metadata.

Reports about OS-level DNS configuration mutation, TUN/TAP packet forwarding,
or rule-language compilation belong to the sibling Lattice components that
own those responsibilities rather than DNS Lattice itself.
