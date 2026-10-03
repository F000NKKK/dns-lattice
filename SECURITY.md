# Security Policy

## Supported Versions

DNS Lattice's crates (`dns-lattice`, `dns-lattice-model`, `dns-lattice-core`)
reached their first stable release, `1.0.0`, published on crates.io. The
public API is now frozen and follows ordinary SemVer within the `1.x` line.

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅ |
| 0.x     | ❌ |

Security fixes target the latest supported `1.x` release.

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

## Resolver cache memory bound

The resolver's answer cache is bounded so that a client cannot exhaust the
host's memory by asking for many distinct names (for example random-subdomain
queries). By default it holds at most 16 MiB, an estimate of the heap its
entries occupy rather than an allocator-exact figure. The limit is enforced
on every insert, not by a background cleaner that could be outrun: each of
the cache's shards owns an equal share of the limit and evicts, one entry at
a time, until it is back within that share. Expired entries go first, then
entries that were never reused, so a flood of one-off names displaces other
one-off names and not the names that are asked for repeatedly. An answer
larger than an eighth of a shard's share is returned to the client but never
stored, and the cache is never flushed as a whole to make room. Cache keys
are hashed with a per-resolver random key and compared in full on every hit,
so crafted names cannot force collisions or make a hit return another
question's answer.

`ResolverBuilder::cache` with `CacheConfig` changes the bound
(`max_bytes`), the shard count (`shards`) and the TTL limits
(`positive_ttl`, `negative_ttl`, `negative_ttl_without_soa`);
`CacheConfig::disabled()` keeps no answers. Size the bound for the host: the
bound covers the cache only, not in-flight queries, connections or the
inbound server's own buffers. Concurrent identical queries are not merged
yet, so a burst of identical misses still sends one upstream query each.

## Scope

The supported `1.x` release surface includes the hand-rolled DNS message model
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
- an inbound UDP answer larger than the documented limit (512 bytes for a
  client without EDNS(0), otherwise the smaller of the client's advertised
  payload size and the configured server maximum), which would increase
  reflection amplification; operators who want the smallest UDP answers can
  set the server maximum to 512;
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
