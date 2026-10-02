//! Domain-name parsing, hashing and comparison: dns-lattice `Name` next to
//! hickory-proto `Name`.
//!
//! - `name_parse/<library>/<short|long>`: `Name::from_ascii` on `a.b` and
//!   on a 5-label, 59-character name.
//! - `name_hash_lookup/<library>/<case>`: `HashMap<Name, u32>::get` on a
//!   map of 1,000 names: a hit with the stored casing (`hit-same-case`), a
//!   hit with different casing (`hit-other-case`), and a miss. The probe
//!   name is built outside the timed section.
//! - `name_eq/<library>`: `==` between two equal names that differ only in
//!   ASCII case.
//!
//! Both libraries compare and hash names case-insensitively, so every hit
//! probe really hits; the set-up asserts that.
//!
//! Run with `cargo bench --bench name` from `bench/resolver`.

use std::collections::HashMap;
use std::hash::Hash;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dns_lattice::model::Name;
use hickory_proto::rr::Name as HkName;

const SHORT: &str = "a.b";
const LONG: &str = "service-frontend.region-eu-west-1.cluster-0007.corp.example";
const MAP_LEN: u32 = 1_000;

fn parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("name_parse");
    for (id, input) in [("short", SHORT), ("long", LONG)] {
        group.bench_with_input(BenchmarkId::new("dns-lattice", id), input, |b, input| {
            b.iter(|| Name::from_ascii(black_box(input)).unwrap())
        });
        group.bench_with_input(BenchmarkId::new("hickory", id), input, |b, input| {
            b.iter(|| HkName::from_ascii(black_box(input)).unwrap())
        });
    }
    group.finish();
}

fn map_name(index: u32) -> String {
    format!("host-{index}.zone-{}.bench.test", index % 16)
}

/// Benchmarks the three lookups for one library's name type.
fn lookups<N: Eq + Hash>(c: &mut Criterion, library: &str, parse: impl Fn(&str) -> N) {
    let map: HashMap<N, u32> = (0..MAP_LEN).map(|i| (parse(&map_name(i)), i)).collect();
    let probes = [
        ("hit-same-case", parse(&map_name(500))),
        ("hit-other-case", parse(&map_name(500).to_ascii_uppercase())),
        ("miss", parse("missing.bench.test")),
    ];
    assert_eq!(map.get(&probes[0].1), Some(&500));
    assert_eq!(map.get(&probes[1].1), Some(&500));
    assert_eq!(map.get(&probes[2].1), None);

    let mut group = c.benchmark_group("name_hash_lookup");
    for (id, probe) in &probes {
        group.bench_with_input(BenchmarkId::new(library, id), probe, |b, probe| {
            b.iter(|| map.get(black_box(probe)).copied())
        });
    }
    group.finish();
}

fn hash_lookup(c: &mut Criterion) {
    lookups(c, "dns-lattice", |s| Name::from_ascii(s).unwrap());
    lookups(c, "hickory", |s| HkName::from_ascii(s).unwrap());
}

fn eq(c: &mut Criterion) {
    let mut group = c.benchmark_group("name_eq");
    let (lower, upper) = (
        Name::from_ascii(LONG).unwrap(),
        Name::from_ascii(&LONG.to_ascii_uppercase()).unwrap(),
    );
    assert!(lower == upper);
    group.bench_function("dns-lattice", |b| {
        b.iter(|| black_box(&lower) == black_box(&upper))
    });
    let (lower, upper) = (
        HkName::from_ascii(LONG).unwrap(),
        HkName::from_ascii(LONG.to_ascii_uppercase()).unwrap(),
    );
    assert!(lower == upper);
    group.bench_function("hickory", |b| {
        b.iter(|| black_box(&lower) == black_box(&upper))
    });
    group.finish();
}

criterion_group!(benches, parse, hash_lookup, eq);
criterion_main!(benches);
