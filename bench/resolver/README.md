# dns-lattice resolver benchmarks

An unpublished benchmark harness that measures dns-lattice next to
[hickory](https://github.com/hickory-dns/hickory-dns) 0.26.x on identical
inputs, in the same run and on the same machine.

This directory is a standalone Cargo workspace. It is not a member of the
repository's root workspace, is never published (`publish = false`), and is
not part of any published crate's archive or dependency graph, so hickory
never becomes a dependency of dns-lattice. Its `Cargo.lock` is not
committed; record the resolved versions (`cargo tree`) with any results you
publish.

## Status

The criterion micro-benchmarks and the loopback client benchmark are in
place: both libraries resolve against one library-neutral upstream over UDP,
TCP, DoT, DoH over HTTP/2, DoH over HTTP/3 and DoQ, with cold and
cache-hit scenarios. A forwarding-server benchmark is planned on top of the
same harness.

## Requirements

- Rust 1.99 or newer (the dns-lattice MSRV).
- Any platform for the micro-benchmarks. No privileges and no network
  access are needed: everything runs in-process.
- Linux for the client benchmark's CPU and memory figures (they read
  `/proc`) and for `scripts/bench-resolver.sh run`. Everything binds to
  `127.0.0.1` on ephemeral ports and needs no privileges.

## Layout

| Path | Contents |
| --- | --- |
| `src/wire.rs` | Hand-written DNS query parsing and deterministic response building. It uses neither library under test, so it can serve as a neutral upstream and as identical codec input for both. |
| `src/fixture.rs` | A throwaway CA and leaf certificate (`dns.bench.test` and `127.0.0.1`), and the one TLS client configuration both libraries share. |
| `src/responder.rs`, `src/bin/responder.rs` | The loopback upstream: UDP, TCP, DoT (pipelined), DoH2, DoH3 and DoQ. Fixed reply latency, A, AAAA, TXT and NXDOMAIN-with-SOA answers, and per-transport counters (queries, connections, handshakes, resumed) served on a stats port. |
| `src/loadgen.rs` | The closed-loop load generator: each worker keeps one query in flight; warm-up, measurement and stop phases; an HDR histogram per run. |
| `src/dl.rs`, `src/hk.rs`, `src/bin/dl-client.rs`, `src/bin/hk-client.rs` | The two contestants behind one interface, and a client binary per library that prints one JSON result. |
| `src/metrics.rs`, `src/cli.rs` | Process CPU and memory from `/proc`; argument handling for the binaries. |
| `variants.tsv` | The client scenarios `scripts/bench-resolver.sh run` executes. |
| `tests/smoke.rs` | Loopback tests of the responder, both contestants, the load loop and the client binaries. |
| `benches/codec.rs` | Message decode and encode, dns-lattice and hickory-proto on the same bytes. |
| `benches/name.rs` | Name parsing, hashing (`HashMap` lookups) and case-insensitive equality, both libraries. |
| `benches/matcher.rs` | `DomainMatcher` and `SplitDnsPolicy` with 10, 1,000 and 100,000 rules (dns-lattice only). |
| `benches/cache.rs` | Resolver cache hits, single task and contended (dns-lattice only). |
| `tests/wire.rs` | Wire-format tests, cross-checked against both libraries' decoders. |

## Micro-benchmarks

| Group | What is timed |
| --- | --- |
| `decode/<library>/<fixture>` | Bytes to an owned message. |
| `encode/<library>/<fixture>` | A decoded message back to bytes; `dns-lattice-into` reuses one buffer. |
| `name_parse/<library>/<short\|long>` | `Name::from_ascii` on `a.b` and on a 5-label, 59-character name. |
| `name_hash_lookup/<library>/<case>` | `HashMap<Name, u32>::get` over 1,000 names: hit with the same casing, hit with other casing, miss. |
| `name_eq/<library>` | `==` between names that differ only in case. |
| `domain_matcher/<rules>/<probe>` | `DomainMatcher::resolve`: exact hit, deep-suffix hit, wildcard hit, miss. |
| `split_dns_policy/<rules>/<probe>` | `SplitDnsPolicy::resolve_group` over the same rules. |
| `cache_hit/<entries>` | `Resolver::resolve` hits with 1, 1,024 and 100,000 cached entries, one task. |
| `cache_hit_contended/<keys>/<tasks>` | 1, 4 and 16 concurrent tasks on 4 worker threads, each on its own keys or all on one key. |

The codec fixtures are responses with an OPT record and compressed answer
owner names, as an upstream sends them: one A record, one AAAA record, ten A
records, a TXT record of about 1.1 KB, and NXDOMAIN with an SOA record.

Things to keep in mind when reading the numbers:

- **Encoded sizes differ.** dns-lattice writes names uncompressed and
  hickory compresses them, so the two encoders do not produce the same
  bytes. Encode throughput is reported against the input fixture length for
  both, and the actual encoded sizes are printed when the `codec` benchmark
  starts.
- **The cache is measured through the public API.** The resolver's cache is
  internal, so `cache_hit` times the whole `Resolver::resolve` hit path
  (routing, the cache lock and lookup, and the cloned response) against an
  in-process upstream that counts its calls. Each benchmark checks that the
  upstream was never called after warm-up, so every timed call is a hit.
- **hickory's cache is not in the micro-benchmarks.** It cannot sit behind
  an in-process upstream; its cache hits belong to the loopback resolver
  benchmark.
- **The rule sets are synthetic.** Rule `i` is `r<i>.bench.test`; a third
  of the rules are exact, a third suffix and a third wildcard. The probes
  are taken from the middle of the set.

## Client benchmark

`dl-client` and `hk-client` run a closed loop (a fixed number of workers,
each with one query in flight) against the responder and print one JSON
document: queries, queries per second, latency percentiles (p50, p90, p99,
p99.9, max), outcome counts, process CPU per 1,000 queries, resident
memory, and the responder's connection and handshake counts during the
measurement. A run is marked `valid: false` (and the binary exits 1) if no
query completed, more than 0.1% of the queries failed, in a warm run the
upstream saw any query during the measurement, or in a cold run the
upstream saw fewer queries than the client completed (beyond a slack of
`--concurrency` in-flight queries at the window edges).

Scenarios (`variants.tsv`):

- **client-\<transport\>**: distinct names per worker, upstream TTL 0, so
  every query goes to the wire; concurrency 16 and 256.
- **mix**: AAAA, TXT (about 1.1 KB) and NXDOMAIN answers over UDP.
- **cache**: all workers share a small set of names that is resolved first
  and served with TTL 3600, so the measurement is answer-cache hits.

Fairness settings, identical for both libraries:

| Setting | Value |
| --- | --- |
| Attempts | One. dns-lattice never retries a backend; hickory's `attempts` counts retries, so it is set to `0` (a test checks that this sends exactly one query). |
| Timeout | 2 s per query. |
| EDNS(0) | On, 1232-byte payload, on every transport. |
| Concurrency limit | hickory `max_active_requests = 256`, at least the highest concurrency, so its default of 32 cannot produce busy errors. |
| TLS | One client configuration (aws-lc-rs, default protocol versions, only the fixture CA trusted). |
| Answer cache | Each library's default. |
| hickory | `num_concurrent_reqs = 1`, no TCP retry on error, no 0x20 case randomization, hosts file off, one name server. |
| Responder | The same process and settings for both; one responder instance per client run. |

Connection model (read this before comparing encrypted-transport rows):
on TCP and DoT dns-lattice reuses and pipelines a small pool of connections
(by default up to 4, with 64 queries in flight on each), whereas hickory
pools and multiplexes connections of its own: one per concurrent worker with
16 workers in a loop. On DoH over HTTP/2 dns-lattice keeps one client and
multiplexes every query over a single connection. On DoQ it keeps a pool of
QUIC connections (by default up to 4, with 64 streams in flight on each) and
opens one stream per query, whereas hickory opens a connection per concurrent
worker. On DoH over HTTP/3 dns-lattice still opens a new connection (and a
new QUIC handshake, resumed when the server issues a ticket) for every query;
that transport moves to pooling in a later change. The responder counters in
each result show the connection counts, so the TCP, DoT, DoH2 and DoQ rows
compare two pooling designs and the DoH3 rows still compare two connection
models, not only two codecs and runtimes. hickory's pooled connections
also have a bounded request queue (32 slots); a burst of more than 32
simultaneous requests onto one already-established connection fails with
a "channel is full" error that the client binary reports under its own
label, not as busy. The closed-loop scenarios do not hit it at
concurrency 256.

## Running

From the repository root:

```sh
# Build the responder and the two clients (release).
scripts/bench-resolver.sh build

# A short local pass over a few scenarios.
scripts/bench-resolver.sh run --variants client-udp-c16,client-dot-c16,cache --reps 1 --duration 2 --warmup 1

# Everything, three repetitions, results kept under a directory.
scripts/bench-resolver.sh run --out target/bench-resolver/results/full
```

`run` writes `meta.json` (commit, toolchain, kernel, resolved versions)
and, per scenario and repetition, `dl.json`, `hk.json` and the responder's
final counters. It pins the clients and the responder to disjoint CPU
halves when `taskset` and at least four CPUs are available
(`--no-pin` disables that), and alternates which library runs first.

The micro-benchmarks:

```sh
# Every micro-benchmark, criterion's default timing.
scripts/bench-resolver.sh micro

# A quick pass, with the console log and criterion estimates kept.
scripts/bench-resolver.sh micro --warm-up 1 --measurement 2 --out target/bench-resolver/micro

# One benchmark, filtered to one group.
scripts/bench-resolver.sh micro --bench codec -- decode
```

Builds go to `target/bench-resolver` (override with `CARGO_TARGET_DIR`).
Plain `cargo` works too, from this directory or with
`--manifest-path bench/resolver/Cargo.toml`:

```sh
cargo test --manifest-path bench/resolver/Cargo.toml
cargo bench --manifest-path bench/resolver/Cargo.toml --bench matcher -- --noplot
```

### Before and after a change

Compare on the same machine, with nothing else running:

```sh
# On the base commit:
scripts/bench-resolver.sh micro --save-baseline before
# On the change:
scripts/bench-resolver.sh micro --baseline before
```

Criterion then reports the change against the saved baseline for every
benchmark.

## Results

No results are recorded here yet. Numbers from a short local run are not
comparable across machines; publish results only together with the
machine, the toolchain and the resolved crate versions.
