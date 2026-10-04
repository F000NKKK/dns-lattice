# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ServerBuilder::edns_udp_payload_size` sets the largest UDP answer the
  inbound server sends to an EDNS(0) client and advertises in its OPT
  record. The default is 1232 bytes; smaller values are raised to 512, and
  setting 512 restores the 1.1 UDP answer size.
- `UdpBackend::with_edns_udp_payload_size` makes the UDP upstream backend
  advertise EDNS(0): a query that carries no OPT record is sent with one
  (the given payload size raised to at least 512, DO clear, no options), so
  the upstream may answer with more than 512 bytes over UDP. It is off by
  default. A query that already has an OPT record is sent unchanged; an
  upstream `FORMERR` or `NOTIMP` without an OPT record makes the backend
  retry once without it, within the same timeout; the OPT record is removed
  from the returned answer; an answer with a nonzero extended RCODE becomes
  `Error::Transport` (so the resolver fails over); a truncated answer still
  falls back to TCP with the original query.
- `dns_lattice::cache::CacheConfig` and `ResolverBuilder::cache` configure
  the resolver's answer cache: `max_bytes` (the memory bound; `0` disables
  the store), `shards`, `positive_ttl`, `negative_ttl` (inclusive TTL clamps,
  in whole seconds), and `negative_ttl_without_soa` (`None` stores no
  negative answer that lacks an SOA, the strict reading of RFC 2308).
  `CacheConfig::disabled()` keeps no answers. The defaults reproduce the
  behaviour listed under Changed.
- `CacheConfig::coalesce` turns in-flight query coalescing on or off (on by
  default; see Changed).
- `observability::CacheEvent` (a `#[non_exhaustive]` enum) and the defaulted
  `ObservabilitySink::record_cache` method deliver cache signals outside the
  ordered `ObserveEvent` stream, so existing sinks compile and behave as
  before. The first event is `CacheEvent::Coalesced`, emitted for a query
  that joined another query's upstream call.
- `Resolver::clear_cache`, `Resolver::purge` and `Resolver::purge_subtree`
  flush the answer cache and return the number of entries removed. `purge`
  removes one name (every upstream group, class and query shape; one record
  type, or all with `None`); `purge_subtree` removes a zone and everything
  below it, matching whole labels only. A flush also stops queries already
  waiting on an upstream call from storing their answer (they are still
  answered), so an answer fetched before a flush never outlives it.
- `Resolver::cache_stats` returns a `dns_lattice::cache::CacheStats`
  snapshot: `entries`, `bytes` (an estimate), `capacity_bytes`, `hits`,
  `misses`, `coalesced`, `inserts`, `evictions`, `expirations` and
  `oversized_rejected` (and `refreshes`, see below). The counters are
  monotonic and survive a flush. `hits` counts queries answered from the
  store at their first lookup; a leader that missed and then found an
  answer another query had just stored counts as a miss, so under
  concurrency `hits` can be slightly below the number of queries the store
  served.
- Opt-in cache prefetch: `dns_lattice::cache::Prefetch` (`new`,
  `threshold_percent`, `min_hits`), `CacheConfig::prefetch`,
  `CacheStats::refreshes` and the events `CacheEvent::RefreshStarted` and
  `CacheEvent::RefreshCompleted` (added to the `#[non_exhaustive]`
  `CacheEvent`). A fresh hit on an entry with at least `min_hits` (default
  2) hits and at most `threshold_percent` (default 10, clamped to 1 to 50)
  of its lifetime left starts one background refresh on the current Tokio
  runtime. The refresh queries the hit's own upstream group without running
  the route hook again, joins the in-flight registry like a miss (so it never
  duplicates an upstream call and a query arriving meanwhile shares its
  result), replaces the entry when the answer is cacheable, and emits cache
  events but no `ObserveEvent`. Each stored entry is refreshed at most once,
  at most 256 refreshes run at a time, a hit outside a Tokio runtime starts
  none, and dropping the `Resolver` aborts the running refreshes. It is off
  by default: without it the resolver still spawns no tasks.
- Opt-in serve-stale (RFC 8767): `dns_lattice::cache::ServeStale` (`new`,
  `max_stale`, `reply_ttl`, `failure_recheck`, `client_timeout`),
  `CacheConfig::serve_stale`, `CacheStats::stale_hits` and
  `CacheEvent::StaleServed`. An expired answer is kept for `max_stale`
  (default one day, at most seven) after its TTL. A query that finds one
  still asks the upstream first; if the resolution fails (every backend
  failed, or `SERVFAIL`/`REFUSED`) it gets the expired answer with every
  record TTL set to `reply_ttl` (default 30 s) and, for a query with an EDNS
  OPT record, Extended DNS Error 3 (Stale Answer, RFC 8914). A failed
  refresh starts a `failure_recheck` window (default 30 s) in which queries
  are answered stale without an upstream call, and queries arriving during a
  refresh share it, so a dead upstream sees at most one call per stale name.
  Only a `NOERROR` or `NXDOMAIN` answer replaces a stored one. With
  `client_timeout` the caller is answered stale once the timeout passes
  while the refresh continues in a background task that stores its answer
  (this needs coalescing and a Tokio runtime, spawns a task bound to the
  `Resolver`, and reports `CacheEvent::RefreshStarted`/`RefreshCompleted`).
  It is off by default; expired answers are then dropped as before.
- Opt-in failure caching (RFC 9520): `dns_lattice::cache::FailureCache`
  (`new`, `initial`, `max`), `CacheConfig::failure_cache`,
  `CacheStats::failure_hits` and `CacheEvent::FailureServed`. A failed
  resolution (an error, or a `SERVFAIL`/`REFUSED` answer) is remembered per
  cache identity for `initial` (default 1 s, clamped to 1 to 300 s), doubling
  per further consecutive failure up to `max` (default 30 s); queries in
  that time get the same error or answer, with their own id, without an
  upstream call. A success clears the backoff, a flush drops it, and a
  stale answer, when serve-stale holds one, takes precedence. It is off by
  default; failures are then never stored. The entries count against the
  cache's byte bound.
- `upstream::PoolConfig` and `upstream::PoolStats` describe upstream
  connection reuse and report its counters. `PoolConfig` holds the policy:
  `max_connections` (default 4, clamped to 1..=16), `max_in_flight` queries
  per connection (default 64, clamped to 1..=256), `idle_timeout` (default
  20 s, at least 1 s) and `max_lifetime` (default 10 minutes, `None` for
  unlimited, otherwise at least 1 s); `PoolConfig::disabled` switches reuse
  off. `PoolStats` is a snapshot of the connection, query, retry, queueing
  and unsolicited-frame counters. The pool core behind them bounds admission
  to `max_connections x max_in_flight` queries in arrival order, shares one
  connection attempt between waiting callers, and ends idle and over-age
  connections.
- `TcpBackend::with_pool`, `DotBackend::with_pool` and the matching
  `pool_stats` snapshot accessors choose the connection-reuse policy of a
  backend and read its counters. `PoolConfig::disabled()` restores the
  earlier behaviour of one connection per query.
- `DohBackend::with_pool` and `DohBackend::pool_stats` choose the
  connection-reuse policy of a DNS-over-HTTPS backend and read its counters.
  The connection counters are exact; `closed_idle`, `closed_error` and
  `unsolicited` stay 0 (hyper does not report why it closed a connection) and
  `closed_lifetime` counts connections that closed after the backend replaced
  its client at `max_lifetime`.
- `DoqBackend::with_pool` and `DoqBackend::pool_stats` choose the
  connection-reuse policy of a DNS-over-QUIC backend and read its counters
  (`unsolicited` is always 0, because a QUIC stream carries only the answer to
  its own query).

### Changed

- `DoqBackend` now keeps a bounded pool of QUIC connections on one shared UDP
  socket and opens one bidirectional stream per query (RFC 9250 section
  4.2), instead of binding a socket and handshaking a connection for every
  query. By default it uses up to 4 connections with 64 concurrent streams
  each (keep `max_in_flight` below the server's own stream limit, commonly
  100; a query that finds the limit reached waits for a stream and ends with
  `Error::Timeout` at its deadline). Idle connections close after the idle
  timeout and every connection is replaced after `max_lifetime`; a replaced
  connection finishes its streams first. Liveness is checked before a
  connection is used. A connection that resets or stops one query's stream
  fails only that query. Dropping the `resolve` future resets the stream
  with `DOQ_REQUEST_CANCELLED` and leaves the connection in use. A new
  connection resumes the TLS session through the shared `ClientConfig`;
  0-RTT stays off. A query whose reused connection was closed is sent once
  more on a fresh connection (only for opcode QUERY and only while its time
  budget lasts); timeouts, TLS errors, answers that do not match the question
  and undecodable answers are never retried. Consequences to plan for: the
  backend keeps a UDP socket and Tokio tasks while alive and belongs to one
  Tokio runtime (use `PoolConfig::disabled()` for a backend shared across
  short-lived runtimes), dropping it closes its connections, and an upstream
  sees one connection carrying the queries of many clients.
  `PoolConfig::disabled()` restores the 1.1 behaviour of an endpoint and a
  connection per query. The time budget of one call is not longer than
  before: connect timeout plus two read timeouts.

- `DohBackend` (HTTP/1.1 and HTTP/2) now keeps one HTTP client per backend
  instead of building one per query. Over HTTP/2 all queries are multiplexed
  over a single connection; over HTTP/1.1 each in-flight query uses its own
  idle or new connection, up to `max_connections x max_in_flight` at once.
  Admission to that bound is in arrival order. Idle connections close after
  `idle_timeout`, and the client is replaced after `max_lifetime` (the old one
  finishes its in-flight queries). HTTP/2 connections send keep-alive pings.
  The TLS configuration, server name and ALPN are fixed at construction, so
  backends never share connections. One call has a single `timeout` covering
  the wait for capacity, the request, the body and a retry, which is not
  longer than before. Pooled sockets have `TCP_NODELAY` set (without it a
  single HTTP/2 connection stalled small frames behind Nagle's algorithm and
  ran at half the throughput with ~40 ms tail latency). While a client has no
  connection (first query, after idle close, after `max_lifetime`), one call
  starts the connection and calls arriving meanwhile wait until that call's
  response headers arrive, bounded by their own `timeout`. A query whose reused connection fails before the
  answer is sent once more (only for opcode QUERY and only while time is left);
  timeouts, TLS errors, HTTP status errors and undecodable answers are never
  retried. Consequences to plan for: the backend keeps sockets and Tokio tasks
  while alive and belongs to one Tokio runtime (use `PoolConfig::disabled()`
  for a backend shared across short-lived runtimes), and dropping it closes
  its connections. `PoolConfig::disabled()` restores the 1.1 behaviour of a
  new client and connection per query. `Doh3Backend` is unchanged and still
  uses one connection per query.
- `dns-lattice` with the `doh` feature depends directly on `tower-service`
  (already part of the dependency tree through hyper-util).
- `TcpBackend` and `DotBackend` now reuse connections by default and pipeline
  queries (RFC 7766 section 6.2.1.1, RFC 7858 section 3.3). Each backend
  owns a small pool (by default up to 4 connections with 64 queries in
  flight each) with one reader task and one writer task per connection; idle
  connections close after 20 s and every connection is replaced after 10
  minutes. The caller's message id is replaced by a per-connection id on the
  wire and restored on the answer. A DoT reconnect still resumes the TLS
  session through the shared `ClientConfig`. Consequences to plan for:
  - a backend now spawns Tokio tasks and holds sockets while it is alive, so
    it must be used from one Tokio runtime (use `PoolConfig::disabled()` for a
    backend shared across short-lived runtimes), and dropping it closes its
    connections;
  - an upstream sees one connection carrying the queries of many clients;
  - a query that fails because a reused connection was closed is sent once
    more on a fresh connection (only for opcode QUERY and only while its
    time budget lasts); timeouts, TLS and validation errors are never
    retried;
  - the error classes are unchanged, with one exception: a reply whose
    message id matches no pending query is an unsolicited frame, which is
    dropped, so such a query ends with `Error::Timeout` instead of
    `Error::Transport`. A connection that receives more than 16 unsolicited
    frames in a row, not counting frames answering queries that were
    cancelled or timed out, is closed;
  - a reply that cannot be decoded closes the connection: the query it
    answered fails with the decode error, and the other queries pending on
    the connection fail with a transport error (and are retried like any
    query on a closed connection);
  - the time budget of one call is not longer than before: connect timeout
    plus two read timeouts for TCP, plus three for DoT.
  `UdpBackend` is unchanged, and its fallback to TCP after a truncated answer
  still uses one connection per query.

- Raised the minimum supported Rust version (MSRV) from 1.93 to 1.99 for
  every crate and the benchmark harness. No public API change.
- Resolver query coalescing, default behaviour: concurrent cache misses for
  the same cache identity now share one upstream query instead of sending
  one each. The first query leads; the others wait for its result and are
  answered from it (their own message id, question and RD bit, AA cleared),
  or receive its error, including for answers that are not cacheable such as
  `SERVFAIL`. A waiting query emits no `UpstreamAttempt` or
  `UpstreamOutcome` event, only `CacheMiss`, `CacheEvent::Coalesced` and the
  terminal event. If the leading `resolve` future is dropped, a waiting
  query takes over and queries the upstream itself; nothing is spawned, so
  this works on any executor. A leader stores its answer before handing it
  over, and does not store an answer fetched before the cache was
  invalidated. Without a store (`CacheConfig::disabled()`) queries are
  still coalesced; `CacheConfig::coalesce(false)` restores one upstream
  query per miss.
- A query carrying an EDNS Client Subnet option, or any EDNS option other
  than NSID, COOKIE, TCP keepalive and Padding, now bypasses the cache and
  coalescing: it goes to the upstream group, is reported as a cache miss and
  its answer is not stored, so a client-specific answer is never shared.
  Previously such a query was answered from, and stored in, the cache.
- The `tokio` dependency gains its `sync` feature (already part of tokio, no
  new crate).

- Resolver cache memory, default behaviour (no public API change beyond the
  Added entry above):
  - the cache is bounded to about 16 MiB (an estimate of the heap its
    entries occupy, not an allocator-exact figure). It used to be unbounded,
    and expired entries stayed in memory until the same question was asked
    again. The limit is enforced on every insert by evicting entries one at
    a time, expired ones first and then entries that were never reused
    (S3-FIFO); the cache is never flushed as a whole;
  - an answer larger than an eighth of one shard's share of the bound is
    returned but no longer stored;
  - the cache is split into shards with one lock each, replacing the single
    lock around one map; the shard count defaults to four per available
    core (at most 64), reduced so a shard keeps at least 256 KiB;
  - the cache key is hashed with a per-resolver random key and compared in
    full on every hit.

- Inbound server EDNS(0), default behaviour:
  - a UDP answer to a client that sends an OPT record may now be up to
    min(the client's advertised payload size raised to 512, 1232 bytes)
    long; it used to be truncated above 512 bytes. A client without an OPT
    record still gets at most 512 bytes;
  - every answer to a query with an OPT record carries exactly one OPT
    record, on every transport: cache hits, Fake IP answers, `SERVFAIL`
    answers and truncated (`TC=1`) UDP answers included. It advertises the
    server's payload size, version 0 and the query's DO bit; an upstream
    OPT record's options and DO bit are kept. An answer to a query without
    an OPT record never carries one;
  - a query with more than one OPT record, or an OPT record that does not
    parse, gets a local `FORMERR` carrying one bare server OPT record
    (server payload size, version 0, DO clear, no options; RFC 6891 §7);
    a query with an EDNS version above 0 gets a local `BADVERS` (extended
    RCODE 1). Neither reaches the resolver.
- Resolver EDNS(0), default behaviour (no public API change):
  - the query's DO bit is part of the cache identity, so a DNSSEC-aware and
    a plain client no longer share an entry;
  - a cached answer is stored without its OPT record, so a hit never
    replays the first client's OPT record or options. A hit for a query
    with an OPT record gets a fresh one (1232 bytes, version 0, the query's
    DO bit, no options); a hit for a query without one gets none;
  - a fresh upstream answer or a Fake IP answer has its OPT record removed
    when the query had none, and gets the fresh OPT record above when the
    query had one but the answer did not.
- Resolver cache, default behaviour (no public API change):
  - a stored record TTL is clamped to at most 86 400 s in a positive answer
    and 3 600 s in a negative one; neither was capped before;
  - a positive entry lives for the minimum TTL over every record in the
    answer, authority and additional sections, not the answer section only;
  - a negative answer without an SOA is still cached for 60 s, but no
    longer than any other record it carries;
  - a cache hit echoes the current query's RD bit and returns AA=0; it
    used to replay the first client's header flags. Record order in every
    section is kept as received;
  - the query's RD bit is part of the cache identity;
  - a query with more or fewer than one question, or an opcode other than
    QUERY, bypasses the cache: it goes to the upstream group (reported as a
    cache miss) and its answer is not stored.

### Fixed

- A cache hit replayed the TTLs the upstream sent, however long the answer
  had been cached. Every record TTL now counts down by the whole seconds
  elapsed since the answer was stored, and stays at least 1 while the entry
  is fresh. The EDNS OPT pseudo-record is never counted down or clamped,
  because its TTL field holds the extended RCODE, version and flags.
- The negative-cache TTL was the SOA `MINIMUM` field alone. It is now
  min(SOA TTL, SOA `MINIMUM`) as RFC 2308 §5 requires, and the served SOA's
  TTL is rewritten to that value and counts down.
- A `SERVFAIL`, `REFUSED` or other error response that carried records was
  cached as a positive answer, and truncated (`TC=1`) answers were cached.
  Only `NOERROR` answers with records, `NXDOMAIN` and `NODATA` answers with
  opcode QUERY, `TC=0` and an EDNS extended RCODE of 0 are cached now; an
  answer whose OPT record does not parse is not cached.
- An answer with a TTL of 0 was inserted into the cache although it could
  never be served, so unique zero-TTL names grew the cache. Such answers are
  no longer stored, and an expired entry is removed when a lookup finds it.
- A cache hit cloned the whole stored answer while holding the cache lock.
  The lock now covers only a reference-count increment; the response is
  built after it is released.

## [1.1.3] - 2026-10-02

### Changed

- Compacted the crate READMEs for crates.io: short sections without
  tables that link to the repository README and ARCHITECTURE. The root
  README installation snippets now name `1.1.3`. No code change.

### Fixed

- The UDP upstream backend received into a 512-byte buffer, although it
  forwards a client's query unchanged, including an EDNS0 OPT record that
  advertises a larger payload. An upstream answer over 512 bytes was cut
  off: on Linux and macOS it then failed to decode and the client got
  `SERVFAIL`; on Windows the receive failed and the resolver moved to the
  next upstream. The backend now receives any UDP DNS payload up to 65535
  bytes. A response with `TC=1` still falls back to TCP as before. No public
  API change.
- The DoQ backend sent the caller's message id, although RFC 9250 requires
  id 0 on the wire; it now sends id 0. The DoH and DoQ backends now return
  the response with the caller's query id, so a forwarded answer from a
  server that replies with id 0 reaches the client with its own id. No
  public API change.

### Security

- Every upstream backend (UDP, TCP, DoT, DoH, DoH3, DoQ) now checks that a
  response answers its query before returning it: `QR` must be set and the
  question section must match (name compared case-insensitively, plus type
  and class). UDP, TCP, and DoT also require the message id to match; DoH
  and DoQ skip the id check because RFC 8484 and RFC 9250 use id 0.
  Previously a response for a different question, a reflected query, or on
  UDP a spoofed datagram with any id could be returned to the client and
  cached. The UDP backend now drops a mismatching or undecodable datagram
  (previously an undecodable one ended the query with `SERVFAIL`) and keeps
  waiting until its timeout; the stream transports report a mismatch as
  `Error::Transport`, so the resolver fails over to the next backend. No
  public API change.

## [1.1.2] - 2026-10-01

### Changed

- Restyled the root and crate READMEs (English and Russian): centered
  header with badges and navigation, grouped key features, a transport and
  platform support matrix, installation per feature, quick start and new
  examples (split DNS with failover, DoT upstream, Fake IP, observability,
  graceful shutdown), performance design notes, a comparison section, API
  overview, and collapsible troubleshooting. All existing technical
  content is kept, and the crate READMEs use absolute links for crates.io.
  Installation snippets now name `1.1.2`. No code change.

## [1.1.1] - 2026-09-30

### Changed

- Raised every workspace dependency requirement to its latest release
  (`async-trait` 0.1.92, `tokio` 1.53.1, `rustls` 0.23.45,
  `rustls-pki-types` 1.15.1, `tokio-rustls` 0.26.6, `webpki-roots` 1.0.9,
  `hyper` 1.11.1, `hyper-util` 0.1.21, `hyper-rustls` 0.27.10, `http`
  1.5.0, `http-body-util` 0.1.5, `bytes` 1.12.1, `base64` 0.23.1, `quinn`
  0.11.12, `rcgen` 0.14.10; `h3` 0.0.8 and `h3-quinn` 0.0.10 were already
  current), matching the versions used across the Lattice ecosystem. No
  public API change; the MSRV stays 1.93.
- Updated the installation snippets in `README.md`/`README.ru.md` and the
  `dns-lattice` crate README to `dns-lattice = "1.1.1"` and
  `tokio = "1.53.1"`.

## [1.1.0] - 2026-09-18

### Changed

- Documentation-only release, no source or public API change. Reconciled
  every published doc (`README.md`/`README.ru.md`, `ARCHITECTURE.md`/`.ru.md`,
  `ROADMAP.md`/`.ru.md`, `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`,
  `index.md`, all three crate READMEs) that still read as pre-1.0.0 after the
  `1.0.0` release: stale `dns-lattice = "0.6"` installation snippets, crate
  `## Status` sections still describing stage 1.0 as upcoming, a
  `README.md`/`README.ru.md` capability-status row still marked "⏳ Stage
  1.0" for the now-shipped SemVer guarantee, and present-tense "Stage 0.6
  validates/adds ..." phrasing that read as ongoing work rather than a
  completed, historical stage. Also generalized every hardcoded "1.0.0 is
  published" status banner to reference the stable `1.x` line instead of a
  single patch version, so this class of edit does not recur on every future
  release.

## [1.0.0] - 2026-09-18

### Added

- First stable release of `dns-lattice`, `dns-lattice-core`, and
  `dns-lattice-model` on crates.io. The public API is frozen; within the
  `1.x` line, additive changes ship as minor releases, compatible fixes as
  patch releases, and a breaking change requires an explicit major version
  bump.
- Stage 1.0 public-API freeze audit: documented every previously-undocumented
  public item (`dns_lattice::observability::ObserveEvent` variant fields) and
  added `#![warn(missing_docs)]` to `dns-lattice`, `dns-lattice-core`, and
  `dns-lattice-model` so full rustdoc coverage is enforced going forward. No
  public API shape changed from `0.6.0`.
- Verified `cargo package` contents and a strict, warnings-denied `cargo doc`
  build across the full feature matrix (`no-default-features`, `dot`, `doh`,
  `doq`, `all-features`) ahead of publication.

## [0.6.0] - 2026-08-15

- Completed stage 0.6 hardening and platform validation. Linux, Windows, and
  macOS now run the workspace checks plus a facade feature matrix covering
  `no-default-features`, `dot`, `doh`, `doq`, and `all-features`; each
  supported feature selection also passes rustdoc with warnings denied.
- Added deterministic property-style regression coverage for DNS message
  parsing and compression bounds, domain-matcher precedence, resolver cache
  identity, and Fake IP TTL/expiry/LRU eviction invariants.
- Added the opt-in `observability::ObservabilitySink` boundary with immutable,
  bounded query/cache/Fake IP/route-hook/upstream/timeout/terminal events.
  Sink output is non-authoritative, callbacks run without resolver locks,
  callback panics are isolated, and sinks receive no resolver/backend handles
  or authority to alter routing, caching, retries, or answers.
- Hardened packaging and release validation: CI lists every workspace package
  archive and runs the hermetic GitHub-release automation regression alongside
  the strict feature/rustdoc matrix. These validation jobs do not publish
  crates or contact external release services.
- Reconciled public documentation, crate-local README files, security/support
  policy, contribution guidance, architecture/status summaries, and EN/RU
  roadmap state so stage 0.6 is recorded as complete. Stage 1.0 is now the
  next development milestone and will freeze/audit the public API before the
  first stable release.

## [0.5.0] - 2026-08-14

- Added `dns_lattice::hooks`: `RouteHook` receives the first DNS question and
  the tentative static upstream group, then either selects one existing group
  with `Use` or preserves it with `Abstain`. `ResolverBuilder::route_hook`
  stores one optional hook. Fake IP local answers remain terminal before the
  hook; ordinary answers are cached with the effective upstream group as part
  of their cache identity, preventing cross-route cache reuse. Hook failures,
  unknown/empty selected groups, and cancellation follow the resolver error
  boundary without static fallback or cache insertion. Hooks own timeout,
  retry, and cancellation cleanup and must not re-enter the same resolver.
- Removed flat root facade aliases in favor of canonical domain modules:
  `core`, `model`, `engine`, `fakeip`, `hooks`, `server`, and `upstream`.

## [0.4.0] - 2026-08-14

- New public `dns_lattice::fakeip` module: `FakeIpPool` configures inclusive
  IPv4 and/or IPv6 ranges, deterministically allocates or reuses one
  synthetic address per DNS name, and reverse-resolves active mappings.
  Each family uses a family-salted FNV-1a candidate, circular probing, and
  independent LRU eviction when full. `FakeIpPolicy` and
  `ResolverBuilder::fake_ip` explicitly enable local synthesis: matching IN
  A/AAAA queries receive synthetic records and canonical in-range IN PTR
  queries receive the live name or NXDOMAIN. Local answers bypass ordinary
  cache/upstream resolution and use no more than the mapping's remaining
  lifetime as their DNS TTL. Mappings have a required whole-second TTL and
  callers may snapshot live mappings (including remaining lifetime and LRU
  order) and restore them as process-local in-memory state; serialization and
  durable persistence are not part of the crate.
- New typed `dns_lattice_core::Error` variants for invalid/unconfigured Fake
  IP pool configuration, invalid snapshots, allocation in a disabled family,
  and Fake IP lifetimes that cannot be represented safely in a DNS TTL
  (`FakeIpTtlOutOfRange`).

## [0.3.0] - 2026-08-13

- The default-off `doh` feature now enables ALPN-negotiated HTTP/1.1 and
  HTTP/2 over TCP/TLS 1.2 or 1.3 for both `DohBackend` and
  `ServerBuilder::doh_addr`. GET and POST are covered end-to-end on both
  HTTP versions; a dual-protocol inbound deployment supplies `h2` and
  `http/1.1` in its `rustls::ServerConfig`.
- `Doh3Backend`/`Doh3BackendConfig` and `ServerBuilder::doh3_addr` add
  RFC 9114 HTTP/3 over QUIC/UDP with ALPN `h3`. HTTP/3 uses TLS 1.3 as
  required by QUIC; existing TCP HTTP/1.1/HTTP/2 DoH APIs remain available
  for TLS 1.2 legacy compatibility. HTTP/3 now preserves the public error
  boundary for QUIC TLS alerts (`Error::Tls`), HTTP/3/transport failures
  (`Error::Transport`), and expired request bounds (`Error::Timeout`).

- DoT now classifies an underlying TCP connection close before a TLS session
  exists as `Error::Transport`; only errors reported by `rustls` during TLS
  negotiation or certificate verification are `Error::Tls`. The upstream
  TCP, DoT, and DoH transport-failure tests now use a controlled loopback
  peer-close fixture instead of relying on platform-specific behavior of a
  TCP connection to a UDP-bound port.

- Stage 0.3 Track A (upstream transport, part 1): new public, async
  `dns_lattice::upstream` module — `UpstreamBackend` trait (replacing
  stage 0.2's crate-private, synchronous `engine::UpstreamBackend`) plus
  baseline `UdpBackend`/`TcpBackend` implementations over
  `tokio`. No EDNS0/OPT support yet; `UdpBackend` falls back to a TCP query
  when a response's `TC` bit is set.
- **Breaking:** `Resolver::resolve` is now `async fn` and must be called
  from inside a `tokio` runtime; `ResolverBuilder::backend` now stores an
  ordered list of backends per upstream group (only the first is used this
  stage — later tracks add failover across the rest).
- New `dns_lattice_core::Error` variants: `Timeout` and `Transport(String)`,
  produced by the new UDP/TCP backends.
- Stage 0.3 Track B (upstream transport, part 2): two new default-off Cargo
  features on `dns-lattice`, `dot` and `doh`. `dot` adds `DotBackend`/
  `DotBackendConfig` (DNS-over-TLS, RFC 7858) over `rustls`/`tokio-rustls`;
  `doh` adds `DohBackend`/`DohBackendConfig`/`DohMethod` (DNS-over-HTTPS,
  RFC 8484, GET and POST wire formats) over `hyper`/`hyper-rustls`. Both
  are independent and additive to the baseline UDP/TCP build, which keeps
  zero TLS/HTTP dependency weight unless explicitly opted into. New
  `dns_lattice_core::Error::Tls(String)` variant for TLS handshake/
  certificate/hostname-verification failures, distinct from `Transport`.
- Stage 0.3 Track C (upstream transport, part 3): new default-off `doq`
  Cargo feature on `dns-lattice` adding `DoqBackend`/`DoqBackendConfig`
  (DNS-over-QUIC, RFC 9250) over `quinn` (TLS 1.3 embedded in QUIC via
  `rustls`, sharing the workspace's `aws-lc-rs` crypto provider with
  `dot`/`doh`). Independent of `dot`/`doh`; opens a fresh QUIC connection
  per query in this stage (no pooling/reuse), one bidirectional stream per
  query, no 0-RTT. No new `dns_lattice_core::Error` variant — reuses
  `Tls`/`Transport` on the same boundary as `dot`/`doh`.
- Stage 0.3 Track D (fallback/failover across upstreams within a group):
  `Resolver::resolve` now tries every backend registered for a matched
  upstream group in registration order instead of only the first — a
  backend failing with `Error::Timeout`, `Error::Transport`, or
  `Error::Tls` falls over to the next backend in the group; the first
  success is cached and returned as before. Once every backend in a group
  has failed, the last attempted backend's error is propagated as-is (no
  new `Error` variant, no synthesized answer, not cached) — this is a
  purely internal behavioral change, `Resolver::resolve`'s signature is
  unchanged.
- Stage 0.3 Track E (inbound server listener, UDP/TCP baseline): new public
  `dns_lattice::server` module — `Server`/`ServerBuilder`, an embeddable
  DNS server engine built on `engine::Resolver`. `ServerBuilder::new` takes
  a shared `Arc<Resolver>`; `udp_addr`/`tcp_addr` configure one or more
  listen addresses; `bind` performs the actual socket binds; `serve`/
  `serve_until` run the UDP receive loop and TCP accept loop concurrently
  (one `tokio` task per datagram, one per TCP connection looping over
  multiple length-prefixed queries per RFC 1035 §4.2.2) until dropped or a
  caller-supplied shutdown future resolves. Oversized UDP answers are
  truncated with `TC=1` set at the existing 512-byte RFC 1035 §4.2.1
  boundary; a `Resolver::resolve` error is answered with a synthesized
  `Rcode::ServFail` response rather than dropped or left to crash the
  listener, while an inbound message that fails to decode at all is
  dropped (no reliable id/question to answer with). Binding a privileged
  port stays the composing application's responsibility, not this crate's.
  Internally, `upstream::framed_query` is now implemented in terms of two
  new crate-private `read_framed`/`write_framed` halves, shared unchanged
  by both `upstream` (client role) and `server` (listener role) — no
  public API change to `upstream`. This is the first slice fulfilling the
  "embeddable DNS server engine" goal named in the architecture doc;
  DoT/DoH/DoQ inbound listeners are deferred to follow-up work behind the
  same `dot`/`doh`/`doq` Cargo features their `upstream` counterparts use.
- Stage 0.3 Track E (inbound server listener, DoT): new
  `ServerBuilder::dot_addr(SocketAddr, Arc<rustls::ServerConfig>)` method,
  behind the existing default-off `dot` Cargo feature, additive to the
  UDP/TCP baseline. Binds a TCP listener, TLS-accepts each connection via
  `tokio_rustls::TlsAcceptor` (caller-supplied `rustls::ServerConfig` — this
  crate does not source certificate material), then reuses the same
  length-prefixed read/write loop the baseline TCP listener uses once the
  handshake completes, so a DoT connection can carry multiple back-to-back
  queries exactly like plain TCP; a TLS handshake failure ends that
  connection without a response, matching the existing undecodable-message
  policy. `Resolver::resolve` errors are still answered with a synthesized
  `Rcode::ServFail`, unchanged from the baseline. No existing `ServerBuilder`/
  `Server` public method signature changes.
- Stage 0.3 Track E (inbound server listener, DoQ): new
  `ServerBuilder::doq_addr(SocketAddr, quinn::ServerConfig)` method, behind
  the existing default-off `doq` Cargo feature, additive to the UDP/TCP/DoT
  listeners. Builds a `quinn::Endpoint` in server mode (ALPN `doq`, RFC
  9250), accepts one fresh bidirectional QUIC stream per query, and reuses
  the same `read_framed`/`write_framed` framing helpers `upstream`'s
  `DoqBackend` already uses on the client side. `Resolver::resolve` errors
  are still answered with a synthesized `Rcode::ServFail`, unchanged from
  the baseline. No existing `ServerBuilder`/`Server` public method
  signature changes.
- Stage 0.3 Track E (inbound server listener, DoH) — the final Track E
  slice, completing Stage 0.3: new `ServerBuilder::doh_addr(SocketAddr,
  Arc<rustls::ServerConfig>, DohListenerConfig)` method and new public
  `DohListenerConfig` type (RFC 8484 request path, defaulting to
  `/dns-query`), behind the existing default-off `doh` Cargo feature,
  additive to the UDP/TCP/DoT/DoQ listeners. Binds a TCP listener,
  TLS-accepts each connection identically to `dot_addr`, then serves
  ALPN-negotiated HTTP/1.1 or HTTP/2 via `hyper_util::server::conn::auto::Builder`, parsing RFC 8484
  GET (`?dns=` base64url query parameter) and POST (`application/
  dns-message` body) requests. A path mismatch responds HTTP 404; an
  unsupported method or a request whose bytes cannot be extracted/decoded
  responds HTTP 400 before `Message::decode` is ever reached; everything
  that decodes responds HTTP 200 with an `application/dns-message` body,
  with `Resolver::resolve` errors still answered as a synthesized
  `Rcode::ServFail` inside that body (not an HTTP error status), matching
  every other transport's error policy adapted to HTTP's request/response
  model. `dns-lattice`'s `doh` Cargo feature now additionally requests
  `hyper`'s `server` feature and `hyper-util`'s `server`/`server-auto`
  features on its existing dependencies (no new crate). No existing
  `ServerBuilder`/`Server` public method signature changes. This closes out
  Track E and Stage 0.3 in full — every planned UDP/TCP/DoT/DoH/DoQ
  upstream backend and inbound listener for this stage has now landed.

## [0.2.0] - 2026-08-02

- Stage 0.2 (resolver engine and static split DNS): `dns-lattice`'s new
  `engine` module (`Resolver`, `ResolverBuilder`) — in-process
  construct/resolve, static split-DNS routing via `SplitDnsPolicy`, a new
  `dns_lattice_core::Error::NoRoute` variant for unroutable queries, and an
  in-memory TTL-respecting answer cache including RFC 2308 negative
  caching. No real network transport yet.

## [0.1.0] - 2026-08-02

- Repository bootstrap: workflow, policies, and packaging scaffolding.
- Stage 0.1 (core model): `dns-lattice-core` (shared `Error`/`Result`) and
  `dns-lattice-model` (DNS message, zone/domain matcher, split-DNS policy
  types) crates, with `dns-lattice` as the facade crate re-exporting them.
