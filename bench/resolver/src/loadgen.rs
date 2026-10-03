//! The closed-loop load generator.
//!
//! [`closed_loop`] runs `concurrency` workers; each issues one query, waits
//! for its outcome, and immediately issues the next, so the offered load
//! follows the system's own speed and there is no coordinated-omission
//! problem to correct for. Both libraries are driven through the same
//! [`Contestant`] interface by the same loop, so everything but the
//! resolution itself is identical.
//!
//! A run has a warm-up phase, whose samples are discarded (it establishes
//! the connection pools and TLS tickets of both sides), and a
//! measurement phase. A query counts toward the measurement if it was
//! *started* during the measurement phase; workers finish their last
//! in-flight query after the phase ends.
//!
//! Each worker owns a rotation of `names_per_worker` names.
//!
//! - [`NameMode::Cold`]: every worker has its own names
//!   (`<mix>-<worker>-<i>.bench.test.`), so with a TTL of 0 neither
//!   library's cache can answer and no two in-flight queries share a name.
//! - [`NameMode::Warm`]: every worker rotates over the same names, which
//!   [`prime`] has resolved once beforehand under a long TTL, so every
//!   measured query should be a cache hit. The caller verifies that through
//!   the responder's query counter.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use serde_json::{Value, json};

use crate::wire::Mix;

/// The result of one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The expected answer arrived: the right type and count for the mix,
    /// or NXDOMAIN for [`Mix::Nx`].
    Ok,
    /// No answer within the timeout.
    Timeout,
    /// An answer arrived, but not the one the mix expects.
    Mismatch,
    /// The library returned an error, named by a short static label.
    Error(&'static str),
}

/// One side of the comparison.
pub trait Contestant: Send + Sync + 'static {
    /// A query prepared once per name, outside the timed section (for
    /// example a parsed name).
    type Prepared: Send + Sync + 'static;

    /// Prepares the query for `fqdn` (fully qualified, trailing dot).
    fn prepare(&self, fqdn: &str, mix: Mix) -> Self::Prepared;

    /// Performs one resolution with no retry and returns its outcome.
    fn query(&self, prepared: &Self::Prepared) -> impl Future<Output = Outcome> + Send;
}

/// How names are assigned to workers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameMode {
    /// Distinct names per worker; meant for a TTL of 0.
    Cold,
    /// The same names for every worker; meant for a long TTL after
    /// [`prime`].
    Warm,
}

impl NameMode {
    /// The command-line name (`cold` or `warm`).
    pub fn as_str(self) -> &'static str {
        match self {
            NameMode::Cold => "cold",
            NameMode::Warm => "warm",
        }
    }

    /// Parses `cold` or `warm`.
    pub fn parse(name: &str) -> Option<NameMode> {
        match name {
            "cold" => Some(NameMode::Cold),
            "warm" => Some(NameMode::Warm),
            _ => None,
        }
    }
}

/// What to run.
#[derive(Debug, Clone, Copy)]
pub struct LoadSpec {
    /// Concurrent workers, each with one query in flight.
    pub concurrency: u32,
    /// Length of the warm-up phase.
    pub warmup: Duration,
    /// Length of the measurement phase.
    pub duration: Duration,
    /// The query mix.
    pub mix: Mix,
    /// Names in each worker's rotation.
    pub names_per_worker: u32,
    /// How names are assigned to workers.
    pub names: NameMode,
}

/// A phase boundary reported to the `on_phase` callback of [`closed_loop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The warm-up ended and the measurement phase begins.
    MeasureStart,
    /// The measurement phase ended.
    MeasureEnd,
}

/// Latency percentiles in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Percentiles {
    /// Median.
    pub p50: u64,
    /// 90th percentile.
    pub p90: u64,
    /// 99th percentile.
    pub p99: u64,
    /// 99.9th percentile.
    pub p999: u64,
    /// Slowest recorded query.
    pub max: u64,
}

/// Counts of [`Outcome`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutcomeCounts {
    /// [`Outcome::Ok`].
    pub ok: u64,
    /// [`Outcome::Timeout`].
    pub timeout: u64,
    /// [`Outcome::Mismatch`].
    pub mismatch: u64,
    /// [`Outcome::Error`], by label.
    pub errors: BTreeMap<&'static str, u64>,
}

impl OutcomeCounts {
    fn add(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::Timeout => self.timeout += 1,
            Outcome::Mismatch => self.mismatch += 1,
            Outcome::Error(label) => *self.errors.entry(label).or_default() += 1,
        }
    }

    fn merge(&mut self, other: OutcomeCounts) {
        self.ok += other.ok;
        self.timeout += other.timeout;
        self.mismatch += other.mismatch;
        for (label, count) in other.errors {
            *self.errors.entry(label).or_default() += count;
        }
    }

    /// Every query that was not [`Outcome::Ok`].
    pub fn failures(&self) -> u64 {
        self.timeout + self.mismatch + self.errors.values().sum::<u64>()
    }
}

/// The result of a measurement phase.
#[derive(Debug, Clone)]
pub struct LoadStats {
    /// Queries counted (started in the measurement phase and finished).
    pub queries: u64,
    /// Queries per second over the measurement phase.
    pub qps: f64,
    /// Latency percentiles of every counted query, successful or not.
    pub lat_us: Percentiles,
    /// What the counted queries returned.
    pub outcomes: OutcomeCounts,
}

impl LoadStats {
    /// The statistics as a JSON object.
    pub fn to_json(&self) -> Value {
        json!({
            "queries": self.queries,
            "qps": self.qps,
            "lat_us": {
                "p50": self.lat_us.p50, "p90": self.lat_us.p90,
                "p99": self.lat_us.p99, "p999": self.lat_us.p999,
                "max": self.lat_us.max,
            },
            "outcomes": {
                "ok": self.outcomes.ok,
                "timeout": self.outcomes.timeout,
                "mismatch": self.outcomes.mismatch,
                "errors": self.outcomes.errors,
            },
        })
    }
}

fn names_for(spec: &LoadSpec, worker: u32) -> Vec<String> {
    (0..spec.names_per_worker)
        .map(|index| match spec.names {
            NameMode::Cold => spec.mix.fqdn(worker, index),
            NameMode::Warm => spec.mix.fqdn(0, index),
        })
        .collect()
}

/// Resolves every warm-mode name once, sequentially, so that a following
/// [`closed_loop`] in [`NameMode::Warm`] hits the cache. Returns the first
/// outcome that was not [`Outcome::Ok`], if any.
pub async fn prime<C: Contestant>(contestant: &C, spec: &LoadSpec) -> Option<Outcome> {
    for fqdn in names_for(spec, 0) {
        let outcome = contestant.query(&contestant.prepare(&fqdn, spec.mix)).await;
        if outcome != Outcome::Ok {
            return Some(outcome);
        }
    }
    None
}

const WARMUP: u8 = 0;
const MEASURE: u8 = 1;
const STOP: u8 = 2;

struct WorkerResult {
    histogram: Histogram<u64>,
    outcomes: OutcomeCounts,
}

/// Runs the load described by `spec` against `contestant`.
///
/// `on_phase` is called (on a runtime thread, so it should return quickly)
/// at the start and the end of the measurement phase, for sampling process
/// CPU and the responder's counters.
pub async fn closed_loop<C, F>(contestant: Arc<C>, spec: &LoadSpec, on_phase: F) -> LoadStats
where
    C: Contestant,
    F: Fn(Phase) + Send + Sync + 'static,
{
    let state = Arc::new(AtomicU8::new(WARMUP));
    let mut workers = Vec::with_capacity(spec.concurrency as usize);
    for worker in 0..spec.concurrency {
        let prepared: Vec<C::Prepared> = names_for(spec, worker)
            .iter()
            .map(|fqdn| contestant.prepare(fqdn, spec.mix))
            .collect();
        let contestant = contestant.clone();
        let state = state.clone();
        workers.push(tokio::spawn(async move {
            run_worker(contestant, prepared, worker, state).await
        }));
    }

    tokio::time::sleep(spec.warmup).await;
    state.store(MEASURE, Ordering::Release);
    let started = Instant::now();
    on_phase(Phase::MeasureStart);
    tokio::time::sleep(spec.duration).await;
    state.store(STOP, Ordering::Release);
    let elapsed = started.elapsed();
    on_phase(Phase::MeasureEnd);

    let mut histogram = new_histogram();
    let mut outcomes = OutcomeCounts::default();
    for worker in workers {
        let result = worker.await.expect("load worker panicked");
        histogram
            .add(&result.histogram)
            .expect("histograms share bounds");
        outcomes.merge(result.outcomes);
    }
    let queries = histogram.len();
    LoadStats {
        queries,
        qps: queries as f64 / elapsed.as_secs_f64(),
        lat_us: Percentiles {
            p50: histogram.value_at_quantile(0.50),
            p90: histogram.value_at_quantile(0.90),
            p99: histogram.value_at_quantile(0.99),
            p999: histogram.value_at_quantile(0.999),
            max: histogram.max(),
        },
        outcomes,
    }
}

fn new_histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds")
}

async fn run_worker<C: Contestant>(
    contestant: Arc<C>,
    prepared: Vec<C::Prepared>,
    worker: u32,
    state: Arc<AtomicU8>,
) -> WorkerResult {
    let mut histogram = new_histogram();
    let mut outcomes = OutcomeCounts::default();
    // Workers start at different offsets so the warm rotation does not
    // have every worker on the same name at once.
    let mut next = worker as usize % prepared.len().max(1);
    let mut iterations = 0_u32;
    loop {
        let phase = state.load(Ordering::Acquire);
        if phase == STOP || prepared.is_empty() {
            break;
        }
        let began = Instant::now();
        let outcome = contestant.query(&prepared[next]).await;
        let micros = began.elapsed().as_micros() as u64;
        if phase == MEASURE {
            histogram.saturating_record(micros.max(1));
            outcomes.add(outcome);
        }
        next = (next + 1) % prepared.len();
        // A cache hit can complete without ever suspending; yielding now and
        // then keeps such workers from starving the phase timer when they
        // outnumber the runtime threads. The yield is outside the timed
        // section and identical for both contestants.
        iterations = iterations.wrapping_add(1);
        if iterations.is_multiple_of(16) {
            tokio::task::yield_now().await;
        }
    }
    WorkerResult {
        histogram,
        outcomes,
    }
}
