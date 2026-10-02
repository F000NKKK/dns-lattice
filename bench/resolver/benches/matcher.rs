//! Split-DNS rule matching at 10, 1,000 and 100,000 rules (dns-lattice
//! only; hickory has no equivalent).
//!
//! Rule `i` is built from `r<i>.bench.test` by a fixed formula, no
//! randomness: `i % 3 == 0` is an exact rule, `1` a suffix rule and `2` a
//! wildcard rule, so each kind is a third of the set. Construction happens
//! outside the timed section. The probes, chosen from the middle of the
//! set:
//!
//! - `exact`: the name of an exact rule;
//! - `deep-suffix`: three labels below a suffix rule;
//! - `wildcard`: one label below a wildcard rule;
//! - `miss`: a name no rule matches.
//!
//! - `domain_matcher/<rules>/<probe>`: `DomainMatcher::resolve`.
//! - `split_dns_policy/<rules>/<probe>`: `SplitDnsPolicy::resolve_group`
//!   over the same rules (8 groups, plus a default group that answers the
//!   miss).
//!
//! Run with `cargo bench --bench matcher` from `bench/resolver`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dns_lattice::model::{DomainMatcher, DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};

const SIZES: [usize; 3] = [10, 1_000, 100_000];

fn rule(index: usize) -> DomainPattern {
    let name = Name::from_ascii(&format!("r{index}.bench.test")).unwrap();
    match index % 3 {
        0 => DomainPattern::exact(name),
        1 => DomainPattern::suffix(name),
        _ => DomainPattern::wildcard(name),
    }
}

/// The first rule index at or after `n / 2` with `index % 3 == kind`.
fn middle(n: usize, kind: usize) -> usize {
    let start = n / 2;
    start + (kind + 3 - start % 3) % 3
}

/// `(probe id, name, expected matching rule index)`.
fn probes(n: usize) -> [(&'static str, Name, Option<usize>); 4] {
    let exact = middle(n, 0);
    let suffix = middle(n, 1);
    let wildcard = middle(n, 2);
    let name = |s: String| Name::from_ascii(&s).unwrap();
    [
        ("exact", name(format!("r{exact}.bench.test")), Some(exact)),
        (
            "deep-suffix",
            name(format!("x.y.z.r{suffix}.bench.test")),
            Some(suffix),
        ),
        (
            "wildcard",
            name(format!("w.r{wildcard}.bench.test")),
            Some(wildcard),
        ),
        ("miss", name("nomatch.other.test".to_owned()), None),
    ]
}

fn group_of(index: usize) -> UpstreamGroupId {
    UpstreamGroupId::new(format!("g{}", index % 8))
}

fn configure(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    n: usize,
) {
    // A linear scan of 100,000 rules takes milliseconds; keep the sample
    // count at criterion's minimum so a short run stays short.
    if n >= 100_000 {
        group.sample_size(10);
    }
}

fn domain_matcher(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_matcher");
    for n in SIZES {
        configure(&mut group, n);
        let mut matcher = DomainMatcher::new();
        for index in 0..n {
            matcher.insert(rule(index), index);
        }
        for (id, probe, expected) in probes(n) {
            assert_eq!(matcher.resolve(&probe).copied(), expected, "{n}/{id}");
            group.bench_with_input(BenchmarkId::new(n.to_string(), id), &probe, |b, probe| {
                b.iter(|| matcher.resolve(black_box(probe)).copied())
            });
        }
    }
    group.finish();
}

fn split_dns_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_dns_policy");
    let default = UpstreamGroupId::new("default");
    for n in SIZES {
        configure(&mut group, n);
        let mut builder = SplitDnsPolicy::builder().default_group(default.clone());
        for index in 0..n {
            builder = builder.rule(rule(index), group_of(index));
        }
        let policy = builder.build();
        for (id, probe, expected) in probes(n) {
            let expected = expected.map_or_else(|| default.clone(), group_of);
            assert_eq!(policy.resolve_group(&probe), Some(&expected), "{n}/{id}");
            group.bench_with_input(BenchmarkId::new(n.to_string(), id), &probe, |b, probe| {
                b.iter(|| policy.resolve_group(black_box(probe)).is_some())
            });
        }
    }
    group.finish();
}

criterion_group!(benches, domain_matcher, split_dns_policy);
criterion_main!(benches);
