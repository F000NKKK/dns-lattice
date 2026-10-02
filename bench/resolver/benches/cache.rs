//! Resolver cache hits through the public API (dns-lattice only).
//!
//! The answer cache is internal to `Resolver`, so it is measured through
//! `Resolver::resolve` with an in-process `UpstreamBackend` that answers
//! one A record with TTL 3600 and counts its calls. Every key is resolved
//! once before measuring; each benchmark then asserts that the backend was
//! not called again, so every timed resolution is a cache hit. The timings
//! include the resolver's whole hit path: question extraction, split-DNS
//! routing (one default group, no rules), the cache lock and lookup, and
//! the cloned response.
//!
//! - `cache_hit/<entries>`: one task on a current-thread runtime, rotating
//!   over up to 1,024 of `entries` pre-populated keys (1, 1,024 and
//!   100,000 entries).
//! - `cache_hit_contended/<keys>/<tasks>`: 1, 4 and 16 tasks on a 4-worker
//!   multi-thread runtime, all resolving at once against 1,024 entries;
//!   `distinct` gives every task its own key range, `identical` makes all
//!   tasks resolve the same key. The time per resolution is the wall time
//!   of the whole batch (including spawning the tasks) divided by the
//!   number of resolutions.
//!
//! hickory's cache cannot sit behind an in-process upstream, so its
//! cache-hit numbers come from the loopback resolver benchmark instead.
//!
//! Run with `cargo bench --bench cache` from `bench/resolver`.

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dns_lattice::core::Result;
use dns_lattice::engine::Resolver;
use dns_lattice::model::{
    Class, Header, Message, Name, Opcode, Question, RData, Rcode, RecordType, ResourceRecord,
    SplitDnsPolicy, UpstreamGroupId,
};
use dns_lattice::upstream::UpstreamBackend;
use dns_lattice_bench_resolver::wire::Mix;
use tokio::runtime::{Builder, Runtime};

/// Keys a single-task benchmark rotates over.
const ROTATION: usize = 1_024;
/// Pre-populated entries of the contention benchmarks.
const CONTENDED_ENTRIES: usize = 1_024;
const WORKERS: usize = 4;

/// Answers every query with one A record (TTL 3600) and counts its calls.
struct CountingBackend {
    calls: Arc<AtomicU64>,
}

#[async_trait]
impl UpstreamBackend for CountingBackend {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = &query.questions[0];
        Ok(Message {
            header: Header {
                qr: true,
                recursion_available: true,
                rcode: Rcode::NoError,
                ..query.header
            },
            questions: query.questions.clone(),
            answers: vec![ResourceRecord {
                name: question.name.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 3600,
                rdata: RData::A([192, 0, 2, 1].into()),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        })
    }
}

fn query(index: usize) -> Message {
    let name = Name::from_ascii(&Mix::A.fqdn(0, index as u32)).unwrap();
    Message {
        header: Header {
            id: index as u16,
            qr: false,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name,
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// A resolver whose cache holds `entries` keys, the queries for them, and
/// the backend call counter (equal to `entries` after warming).
fn warmed(runtime: &Runtime, entries: usize) -> (Arc<Resolver>, Arc<Vec<Message>>, Arc<AtomicU64>) {
    let calls = Arc::new(AtomicU64::new(0));
    let group = UpstreamGroupId::new("default");
    let resolver = Resolver::builder(
        SplitDnsPolicy::builder()
            .default_group(group.clone())
            .build(),
    )
    .backend(
        group,
        CountingBackend {
            calls: Arc::clone(&calls),
        },
    )
    .build();
    let queries: Vec<Message> = (0..entries).map(query).collect();
    runtime.block_on(async {
        for query in &queries {
            resolver.resolve(query).await.unwrap();
        }
    });
    assert_eq!(calls.load(Ordering::Relaxed), entries as u64);
    (Arc::new(resolver), Arc::new(queries), calls)
}

fn assert_all_hits(calls: &AtomicU64, entries: usize) {
    assert_eq!(
        calls.load(Ordering::Relaxed),
        entries as u64,
        "the upstream was called after warm-up: not every resolution was a cache hit"
    );
}

fn single_task(c: &mut Criterion) {
    let runtime = Builder::new_current_thread().build().unwrap();
    let mut group = c.benchmark_group("cache_hit");
    group.throughput(Throughput::Elements(1));
    for entries in [1, 1_024, 100_000] {
        let (resolver, queries, calls) = warmed(&runtime, entries);
        let rotation = &queries[..entries.min(ROTATION)];
        let resolver = &*resolver;
        group.bench_function(BenchmarkId::from_parameter(entries), |b| {
            let mut next = 0;
            b.to_async(&runtime).iter(|| {
                let query = &rotation[next % rotation.len()];
                next += 1;
                resolver.resolve(black_box(query))
            })
        });
        assert_all_hits(&calls, entries);
    }
    group.finish();
}

fn contended(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .build()
        .unwrap();
    let (resolver, queries, calls) = warmed(&runtime, CONTENDED_ENTRIES);
    let mut group = c.benchmark_group("cache_hit_contended");
    group.throughput(Throughput::Elements(1));
    for keys in ["distinct", "identical"] {
        for tasks in [1usize, 4, 16] {
            group.bench_function(BenchmarkId::new(keys, tasks), |b| {
                b.iter_custom(|iters| {
                    if iters == 0 {
                        return Duration::ZERO;
                    }
                    let per_task = iters.div_ceil(tasks as u64);
                    let stride = CONTENDED_ENTRIES / tasks;
                    let start = Instant::now();
                    runtime.block_on(async {
                        let handles: Vec<_> = (0..tasks)
                            .map(|task| {
                                let resolver = Arc::clone(&resolver);
                                let queries = Arc::clone(&queries);
                                tokio::spawn(async move {
                                    for i in 0..per_task as usize {
                                        let index = match keys {
                                            "distinct" => task * stride + i % stride,
                                            _ => 0,
                                        };
                                        black_box(resolver.resolve(&queries[index]).await.unwrap());
                                    }
                                })
                            })
                            .collect();
                        for handle in handles {
                            handle.await.unwrap();
                        }
                    });
                    let elapsed = start.elapsed();
                    // Scale to exactly `iters` resolutions.
                    let done = per_task * tasks as u64;
                    Duration::from_secs_f64(elapsed.as_secs_f64() * iters as f64 / done as f64)
                })
            });
        }
    }
    group.finish();
    assert_all_hits(&calls, CONTENDED_ENTRIES);
}

criterion_group!(benches, single_task, contended);
criterion_main!(benches);
