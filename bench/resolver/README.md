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

The criterion micro-benchmarks below are in place. A loopback resolver
benchmark (both libraries resolving against one library-neutral upstream
over UDP, TCP, DoT, DoH and DoQ) and a forwarding-server benchmark are
planned on top of the same harness.

## Requirements

- Rust 1.93 or newer (the dns-lattice MSRV).
- Any platform for the micro-benchmarks. No privileges and no network
  access are needed: everything runs in-process.

## Layout

| Path | Contents |
| --- | --- |
| `src/wire.rs` | Hand-written DNS query parsing and deterministic response building. It uses neither library under test, so it can serve as a neutral upstream and as identical codec input for both. |
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

## Running

From the repository root:

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
