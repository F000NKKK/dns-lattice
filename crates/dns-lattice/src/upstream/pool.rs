//! Upstream connection reuse: the public [`PoolConfig`] and [`PoolStats`]
//! types and the transport-independent pool core the connection-reusing
//! backends are built on.
//!
//! # Pool model
//!
//! One pool belongs to exactly one backend instance, so a connection can
//! never be re-targeted to another upstream and two backends never share a
//! connection. A pool hands out [`Lease`]s: a lease is one admitted query on
//! one live connection, and it is released (even if the caller's future is
//! dropped) when the lease is dropped.
//!
//! - **Admission.** A semaphore of `max_connections x max_in_flight` permits
//!   bounds the leases a pool can hold. The semaphore is fair, so callers
//!   over capacity are served in arrival order and give up with
//!   [`Error::Timeout`] when their deadline passes instead of growing
//!   memory. Because the permits equal the total capacity, a caller that
//!   holds a permit can always be placed on a live connection or on one the
//!   pool may still open.
//! - **Choice.** Among live, non-draining connections the pool picks the one
//!   with the fewest leases. A connection below a quarter of
//!   `max_in_flight` (at least 1) is used as is; above that the pool opens
//!   another connection, up to `max_connections`, in the background while
//!   the caller keeps using the least loaded one.
//! - **Connect de-duplication.** At most one connect is in progress per
//!   pool, run in a task the pool owns, so a caller that is dropped never
//!   strands the callers waiting for the same connect. Every waiter receives
//!   the same outcome, and a failure is fanned out as a clone of the error,
//!   so an unreachable upstream costs one attempt per round rather than one
//!   per query. After a failed connect the pool does not start background
//!   scale-up connects for [`SCALE_RETRY_BACKOFF`].
//! - **Lifecycle.** A single janitor task per pool closes connections that
//!   were idle for `idle_timeout` and rotates connections that reached
//!   `max_lifetime`: a connection past its lifetime stops taking new leases
//!   (it is draining) and is closed when its last lease ends or after a
//!   grace period, whichever comes first. A draining connection is not
//!   counted against `max_connections`, so rotation never stalls callers; the
//!   overshoot is bounded by the grace period.
//! - **Ownership.** The pool owns every task it starts through an
//!   abort-on-drop handle, and the tasks hold only weak references back to
//!   it, so dropping the pool aborts them and closes every connection. There
//!   is no reference cycle.
//! - **Locking.** State lives behind one `std` mutex that is only held for
//!   short synchronous sections and never across an `.await` (clippy's
//!   `await_holding_lock` is denied for this module). Registration of a
//!   lease is synchronous, so dropping an `acquire` future at any `.await`
//!   cannot leak a permit or a lease.
//!
//! The wire-id table, [`PendingTable`], is the per-connection half a
//! multiplexing engine needs: a random-start allocator whose ids are unique
//! among pending and orphaned (cancelled) queries.

#![deny(clippy::await_holding_lock)]

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use dns_lattice_core::{Error, Result};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, watch};
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until, timeout_at};

/// Default number of connections a pool opens at most.
const DEFAULT_MAX_CONNECTIONS: usize = 4;
/// Largest accepted `max_connections`.
const MAX_CONNECTIONS_LIMIT: usize = 16;
/// Default number of in-flight queries per connection.
const DEFAULT_MAX_IN_FLIGHT: usize = 64;
/// Largest accepted `max_in_flight`.
const MAX_IN_FLIGHT_LIMIT: usize = 256;
/// Default idle timeout.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
/// Smallest accepted idle timeout.
const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
/// Default maximum connection lifetime.
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Smallest accepted maximum lifetime.
const MIN_MAX_LIFETIME: Duration = Duration::from_secs(1);
/// Consecutive deadline expiries on one connection, without a success in
/// between, after which the connection is considered half-open and dropped.
const CONSECUTIVE_TIMEOUT_LIMIT: u32 = 3;
/// How long after a failed connect the pool refuses to start a background
/// scale-up connect, so a failing upstream is not hammered by every query.
pub(crate) const SCALE_RETRY_BACKOFF: Duration = Duration::from_secs(1);
/// Largest number of slots a [`PendingTable`] can address (the wire id is
/// 16 bits wide, and one id is always left free so allocation terminates).
const MAX_TABLE_CAPACITY: usize = u16::MAX as usize;

/// Connection-reuse policy of a transport backend.
///
/// A pool keeps up to [`max_connections`](Self::max_connections) connections
/// to one upstream and multiplexes up to
/// [`max_in_flight`](Self::max_in_flight) queries on each, so a query does not
/// pay a TCP, TLS or QUIC handshake. The policy is bounded: the memory a pool
/// can hold is at most `max_connections x max_in_flight x message size`
/// (65 535 bytes at the worst), and callers beyond that capacity queue in
/// arrival order and fail with a timeout instead of growing memory.
///
/// [`PoolConfig::new`] (the [`Default`]) enables reuse with 4 connections, 64
/// in-flight queries per connection, a 20 second idle timeout and a 10 minute
/// maximum connection lifetime. [`PoolConfig::disabled`] switches reuse off:
/// every query then opens its own connection. Numeric settings are clamped
/// into their valid range rather than rejected, so the bounds hold for any
/// input; the builder methods keep a disabled configuration disabled.
///
/// Reusing a connection means one upstream connection carries the queries of
/// many clients, so the upstream can correlate them more easily than with one
/// connection per query.
///
/// Pass a configuration to [`TcpBackend::with_pool`](super::TcpBackend::with_pool)
/// (and the matching `with_pool` of the other connection-reusing backends);
/// [`TcpBackend::pool_stats`](super::TcpBackend::pool_stats) reports the
/// resulting [`PoolStats`].
#[cfg_attr(feature = "dot", doc = "")]
#[cfg_attr(
    feature = "dot",
    doc = "The DoT backend takes it through [`DotBackend::with_pool`](super::DotBackend::with_pool)."
)]
///
/// # Example
///
/// ```
/// use std::time::Duration;
///
/// use dns_lattice::upstream::PoolConfig;
///
/// let config = PoolConfig::new()
///     .max_connections(2)
///     .max_in_flight(32)
///     .idle_timeout(Duration::from_secs(30))
///     .max_lifetime(None);
/// assert!(config.is_enabled());
/// assert!(!PoolConfig::disabled().is_enabled());
/// ```
#[derive(Debug, Clone)]
pub struct PoolConfig {
    enabled: bool,
    max_connections: usize,
    max_in_flight: usize,
    idle_timeout: Duration,
    max_lifetime: Option<Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig::new()
    }
}

impl PoolConfig {
    /// The default policy: reuse on, 4 connections, 64 in-flight queries per
    /// connection, a 20 second idle timeout and a 10 minute maximum lifetime.
    #[must_use]
    pub fn new() -> Self {
        PoolConfig {
            enabled: true,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
        }
    }

    /// A policy with connection reuse switched off: every query opens its own
    /// connection and closes it afterwards, as the backends did before
    /// connection reuse existed.
    ///
    /// The numeric settings keep their defaults and are ignored while the
    /// policy is disabled.
    #[must_use]
    pub fn disabled() -> Self {
        PoolConfig {
            enabled: false,
            ..PoolConfig::new()
        }
    }

    /// Whether connections are reused (`false` for
    /// [`PoolConfig::disabled`]).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the largest number of connections the pool keeps open to the
    /// upstream. The default is 4; the value is clamped to `1..=16`.
    ///
    /// The limit applies to connections that take new queries. A connection
    /// that reached its [`max_lifetime`](Self::max_lifetime) is replaced
    /// while it finishes its in-flight queries, so old and new connections
    /// may briefly overlap.
    #[must_use]
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n.clamp(1, MAX_CONNECTIONS_LIMIT);
        self
    }

    /// Sets the largest number of queries in flight on one connection. The
    /// default is 64; the value is clamped to `1..=256`. A value of 1 sends
    /// one query at a time per connection, for servers that do not pipeline;
    /// raise [`max_connections`](Self::max_connections) to compensate.
    ///
    /// Together with `max_connections` this bounds the pool: at most
    /// `max_connections x max_in_flight` queries are admitted at once.
    #[must_use]
    pub fn max_in_flight(mut self, n: usize) -> Self {
        self.max_in_flight = n.clamp(1, MAX_IN_FLIGHT_LIMIT);
        self
    }

    /// Sets how long a connection without any query may stay open before the
    /// pool closes it. The default is 20 seconds; shorter values are raised
    /// to 1 second.
    #[must_use]
    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d.max(MIN_IDLE_TIMEOUT);
        self
    }

    /// Sets the longest a connection is used. After this age a connection
    /// stops taking new queries and is closed once its in-flight queries end
    /// (or after a short grace period), so a new connection re-verifies the
    /// server certificate and re-resolves the upstream. The default is 10
    /// minutes; `None` keeps connections until they fail or go idle. A
    /// `Some` value shorter than 1 second is raised to 1 second.
    #[must_use]
    pub fn max_lifetime(mut self, d: Option<Duration>) -> Self {
        self.max_lifetime = d.map(|d| d.max(MIN_MAX_LIFETIME));
        self
    }

    /// The configured `max_connections` (already clamped).
    pub(crate) fn max_connections_value(&self) -> usize {
        self.max_connections
    }

    /// The configured `max_in_flight` (already clamped).
    pub(crate) fn max_in_flight_value(&self) -> usize {
        self.max_in_flight
    }

    /// The configured idle timeout (already raised to its minimum).
    pub(crate) fn idle_timeout_value(&self) -> Duration {
        self.idle_timeout
    }

    /// The configured maximum lifetime (already raised to its minimum).
    pub(crate) fn max_lifetime_value(&self) -> Option<Duration> {
        self.max_lifetime
    }

    /// Total number of queries a pool admits at once.
    pub(crate) fn capacity(&self) -> usize {
        self.max_connections * self.max_in_flight
    }
}

/// A snapshot of one backend's connection-pool counters, returned by
/// [`TcpBackend::pool_stats`](super::TcpBackend::pool_stats) and the matching
/// method of the other connection-reusing backends.
///
/// The counters are read individually with relaxed atomics, so under load the
/// values are each correct but not an atomic cut across all of them. A
/// backend whose connection reuse is disabled reports all zeros.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub(crate) connections_open: u64,
    pub(crate) connections_opened: u64,
    pub(crate) closed_idle: u64,
    pub(crate) closed_lifetime: u64,
    pub(crate) closed_error: u64,
    pub(crate) in_flight: u64,
    pub(crate) queries: u64,
    pub(crate) reused_queries: u64,
    pub(crate) retries: u64,
    pub(crate) queued: u64,
    pub(crate) unsolicited: u64,
}

impl PoolStats {
    /// Connections currently open, including connections that are draining
    /// after reaching their maximum lifetime.
    #[must_use]
    pub fn connections_open(&self) -> u64 {
        self.connections_open
    }

    /// Connections opened since the backend was created.
    #[must_use]
    pub fn connections_opened(&self) -> u64 {
        self.connections_opened
    }

    /// Connections closed because they were idle for the idle timeout.
    #[must_use]
    pub fn closed_idle(&self) -> u64 {
        self.closed_idle
    }

    /// Connections closed because they reached their maximum lifetime.
    #[must_use]
    pub fn closed_lifetime(&self) -> u64 {
        self.closed_lifetime
    }

    /// Connections closed because they failed (the peer closed or reset
    /// them, an I/O error occurred, or repeated queries timed out).
    #[must_use]
    pub fn closed_error(&self) -> u64 {
        self.closed_error
    }

    /// Queries currently admitted and not yet finished.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }

    /// Queries admitted since the backend was created.
    #[must_use]
    pub fn queries(&self) -> u64 {
        self.queries
    }

    /// Queries served by a connection that had already answered one.
    #[must_use]
    pub fn reused_queries(&self) -> u64 {
        self.reused_queries
    }

    /// Queries sent again on a fresh connection after a reused connection
    /// failed.
    #[must_use]
    pub fn retries(&self) -> u64 {
        self.retries
    }

    /// Calls that had to wait for capacity (for a free slot or for a
    /// connection to be opened) before being served.
    #[must_use]
    pub fn queued(&self) -> u64 {
        self.queued
    }

    /// Frames received on a connection that matched no pending query.
    #[must_use]
    pub fn unsolicited(&self) -> u64 {
        self.unsolicited
    }
}

/// Relaxed atomic counters behind [`PoolStats`].
#[derive(Debug, Default)]
struct Counters {
    open: AtomicU64,
    opened: AtomicU64,
    closed_idle: AtomicU64,
    closed_lifetime: AtomicU64,
    closed_error: AtomicU64,
    in_flight: AtomicU64,
    queries: AtomicU64,
    reused_queries: AtomicU64,
    retries: AtomicU64,
    queued: AtomicU64,
    /// Shared with the connections' reader tasks through [`PoolHooks`].
    unsolicited: Arc<AtomicU64>,
}

/// What a connection's background tasks may report to the pool that owns it.
///
/// It holds only a counter, never the pool, so a task that keeps it alive
/// cannot keep the pool alive.
#[derive(Debug, Clone)]
pub(crate) struct PoolHooks {
    unsolicited: Arc<AtomicU64>,
}

impl PoolHooks {
    /// Counts one frame that matched no pending query.
    pub(crate) fn record_unsolicited(&self) {
        Counters::bump(&self.unsolicited);
    }
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn drop_one(counter: &AtomicU64) {
        // Saturating at zero keeps a bookkeeping bug from wrapping a gauge to
        // `u64::MAX`.
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
    }

    fn snapshot(&self) -> PoolStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        PoolStats {
            connections_open: get(&self.open),
            connections_opened: get(&self.opened),
            closed_idle: get(&self.closed_idle),
            closed_lifetime: get(&self.closed_lifetime),
            closed_error: get(&self.closed_error),
            in_flight: get(&self.in_flight),
            queries: get(&self.queries),
            reused_queries: get(&self.reused_queries),
            retries: get(&self.retries),
            queued: get(&self.queued),
            unsolicited: get(&self.unsolicited),
        }
    }
}

/// An owned task handle that aborts the task when dropped.
#[derive(Debug)]
pub(crate) struct AbortOnDrop(AbortHandle);

impl AbortOnDrop {
    /// Wraps `handle` so the task is aborted when the guard is dropped.
    pub(crate) fn new(handle: AbortHandle) -> Self {
        AbortOnDrop(handle)
    }

    /// Whether the task has already completed.
    pub(crate) fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    /// Aborts the task now, without waiting for the guard to be dropped.
    pub(crate) fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How a pool opens, probes and closes the connections of one upstream.
///
/// Implemented once per transport (and by a fake in the tests). The pool owns
/// the connections it opens; the connector only describes how to make and
/// inspect them.
pub(crate) trait Connector: Send + Sync + 'static {
    /// The connection type handed to leases. Its background tasks (readers,
    /// writers, QUIC drivers) should be held through [`AbortOnDrop`] so they
    /// end when the pool drops the connection.
    type Conn: Send + Sync + 'static;

    /// Opens a new connection. It runs in a task owned by the pool and must
    /// bound itself with the transport's own connect timeout (a transport
    /// must pass its `connect_timeout` here): a connect that never completes
    /// would keep every caller waiting until its own deadline, and the pool
    /// only stops the connect when the pool is dropped. `hooks` lets the
    /// connection's tasks report to the pool's counters.
    fn connect(&self, hooks: PoolHooks) -> impl Future<Output = Result<Self::Conn>> + Send;

    /// Whether the connection is still usable. It is called while the pool's
    /// state lock is held, so it must be a cheap, synchronous check that
    /// never blocks.
    fn is_alive(&self, conn: &Self::Conn) -> bool;

    /// Closes a connection the pool has retired (idle, rotated, failed or at
    /// pool drop). It is called outside the pool's state lock and must not
    /// block; the default does nothing, relying on dropping the connection.
    fn close(&self, conn: &Self::Conn) {
        let _ = conn;
    }
}

/// The outcome of the connect in progress: `None` until it finishes.
type ConnectState = Option<Result<()>>;

/// The connect currently in progress.
struct Connecting {
    epoch: u64,
    tx: watch::Sender<ConnectState>,
    // Held for abort-on-drop only.
    _task: AbortOnDrop,
}

/// Bookkeeping for one open connection.
struct Entry<C> {
    id: u64,
    conn: Arc<C>,
    opened_at: Instant,
    last_active: Instant,
    in_flight: usize,
    /// The connection has completed at least one query.
    answered: bool,
    /// Consecutive deadline expiries since the last success.
    timeouts: u32,
    /// Set once the connection passed its maximum lifetime.
    draining_since: Option<Instant>,
}

/// Why a connection was retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseReason {
    Idle,
    Lifetime,
    Error,
}

/// Mutable pool state, guarded by [`Shared::state`].
struct State<C> {
    entries: Vec<Entry<C>>,
    next_entry_id: u64,
    next_epoch: u64,
    connecting: Option<Connecting>,
    last_connect_failure: Option<Instant>,
    janitor: Option<AbortOnDrop>,
    /// The instant the janitor is currently sleeping until, so a lease that
    /// ends earlier than that can wake it.
    janitor_deadline: Option<Instant>,
}

/// What the choice step decided for one caller.
enum Pick {
    /// Lease the connection at `idx`; also start a background connect when
    /// `scale_up` is set.
    Use { idx: usize, scale_up: bool },
    /// No connection has room: wait for the connect in progress, starting one
    /// first when `start` is set.
    Wait { start: bool },
    /// Neither a connection with room nor room for a new one. The admission
    /// semaphore makes this unreachable; it is reported as a transport error
    /// rather than a panic.
    Exhausted,
}

struct Shared<K: Connector> {
    config: PoolConfig,
    drain_grace: Duration,
    connector: Arc<K>,
    admission: Arc<Semaphore>,
    state: Mutex<State<K::Conn>>,
    counters: Counters,
    wake: Arc<Notify>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn after(instant: Instant, duration: Duration) -> Option<Instant> {
    instant.checked_add(duration)
}

impl<K: Connector> Shared<K> {
    fn retire(
        &self,
        st: &mut State<K::Conn>,
        idx: usize,
        reason: CloseReason,
        closing: &mut Vec<Arc<K::Conn>>,
    ) {
        let entry = st.entries.remove(idx);
        Counters::drop_one(&self.counters.open);
        let counter = match reason {
            CloseReason::Idle => &self.counters.closed_idle,
            CloseReason::Lifetime => &self.counters.closed_lifetime,
            CloseReason::Error => &self.counters.closed_error,
        };
        Counters::bump(counter);
        closing.push(entry.conn);
    }

    /// Retires every connection that is dead, idle, past its lifetime and
    /// idle, or draining past its grace period, and marks connections that
    /// just reached their lifetime as draining.
    fn sweep_locked(&self, st: &mut State<K::Conn>, now: Instant, closing: &mut Vec<Arc<K::Conn>>) {
        let lifetime = self.config.max_lifetime_value();
        let idle = self.config.idle_timeout_value();
        let mut i = 0;
        while i < st.entries.len() {
            let entry = &mut st.entries[i];
            let reason = if !self.connector.is_alive(&entry.conn) {
                Some(CloseReason::Error)
            } else {
                if entry.draining_since.is_none()
                    && lifetime
                        .and_then(|l| after(entry.opened_at, l))
                        .is_some_and(|t| now >= t)
                {
                    entry.draining_since = Some(now);
                }
                match entry.draining_since {
                    Some(since) => (entry.in_flight == 0
                        || after(since, self.drain_grace).is_some_and(|t| now >= t))
                    .then_some(CloseReason::Lifetime),
                    None => (entry.in_flight == 0
                        && after(entry.last_active, idle).is_some_and(|t| now >= t))
                    .then_some(CloseReason::Idle),
                }
            };
            match reason {
                Some(reason) => self.retire(st, i, reason, closing),
                None => i += 1,
            }
        }
    }

    /// The earliest instant a connection needs attention.
    fn next_deadline_locked(&self, st: &State<K::Conn>) -> Option<Instant> {
        let lifetime = self.config.max_lifetime_value();
        let idle = self.config.idle_timeout_value();
        let mut next: Option<Instant> = None;
        let mut consider = |candidate: Option<Instant>| {
            if let Some(candidate) = candidate {
                next = Some(next.map_or(candidate, |n| n.min(candidate)));
            }
        };
        for entry in &st.entries {
            match entry.draining_since {
                Some(since) => consider(after(since, self.drain_grace)),
                None => consider(lifetime.and_then(|l| after(entry.opened_at, l))),
            }
            if entry.in_flight == 0 {
                consider(after(entry.last_active, idle));
            }
        }
        next
    }

    fn close_all(&self, closing: Vec<Arc<K::Conn>>) {
        for conn in closing {
            self.connector.close(&conn);
        }
    }

    fn scale_suppressed(st: &State<K::Conn>, now: Instant) -> bool {
        st.last_connect_failure
            .and_then(|t| after(t, SCALE_RETRY_BACKOFF))
            .is_some_and(|until| now < until)
    }

    /// Chooses where one caller goes. With `fresh` the caller wants a
    /// connection that has not answered a query yet (a retry after a reused
    /// connection failed): an existing one is used when there is one, a
    /// connect is waited for or started when there is room for one, and only
    /// a pool already at `max_connections` falls back to the least loaded
    /// connection.
    fn pick(&self, st: &State<K::Conn>, now: Instant, fresh: bool) -> Pick {
        let cap = self.config.max_in_flight_value();
        let max_connections = self.config.max_connections_value();
        let threshold = (cap / 4).max(1);
        let live = st
            .entries
            .iter()
            .filter(|e| e.draining_since.is_none())
            .count();
        let connecting = st.connecting.is_some();
        let usable = |e: &Entry<K::Conn>| e.draining_since.is_none() && e.in_flight < cap;
        let fresh_best = if fresh {
            st.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| usable(e) && !e.answered)
                .min_by_key(|(_, e)| e.in_flight)
        } else {
            None
        };
        if fresh && fresh_best.is_none() && (connecting || live < max_connections) {
            return Pick::Wait { start: !connecting };
        }
        let best = fresh_best.or_else(|| {
            st.entries
                .iter()
                .enumerate()
                .filter(|(_, e)| usable(e))
                .min_by_key(|(_, e)| e.in_flight)
        });
        match best {
            Some((idx, entry)) => Pick::Use {
                idx,
                scale_up: entry.in_flight >= threshold
                    && !connecting
                    && live < max_connections
                    && !Self::scale_suppressed(st, now),
            },
            None if connecting => Pick::Wait { start: false },
            None if live < max_connections => Pick::Wait { start: true },
            None => Pick::Exhausted,
        }
    }

    /// Starts the pool's connect task and records it as the connect in
    /// progress. Must be called inside a Tokio runtime, with no connect
    /// already in progress.
    fn start_connect_locked(this: &Arc<Self>, st: &mut State<K::Conn>) {
        let epoch = st.next_epoch;
        st.next_epoch += 1;
        let (tx, _rx) = watch::channel(None);
        let handle = tokio::spawn(run_connect(
            Arc::downgrade(this),
            Arc::clone(&this.connector),
            epoch,
        ));
        st.connecting = Some(Connecting {
            epoch,
            tx,
            _task: AbortOnDrop::new(handle.abort_handle()),
        });
    }

    fn ensure_janitor_locked(this: &Arc<Self>, st: &mut State<K::Conn>) {
        if st.janitor.as_ref().is_some_and(|j| !j.is_finished()) {
            return;
        }
        let handle = tokio::spawn(run_janitor(Arc::downgrade(this), Arc::clone(&this.wake)));
        st.janitor = Some(AbortOnDrop::new(handle.abort_handle()));
        st.janitor_deadline = None;
    }

    /// Records the outcome of the connect task `epoch` and wakes its
    /// waiters.
    fn finish_connect(this: &Arc<Self>, epoch: u64, result: Result<K::Conn>) {
        let now = Instant::now();
        let mut stale = None;
        let notify = {
            let mut st = lock(&this.state);
            match st.connecting.take() {
                Some(connecting) if connecting.epoch == epoch => {
                    let outcome = match result {
                        Ok(conn) => {
                            let id = st.next_entry_id;
                            st.next_entry_id += 1;
                            st.entries.push(Entry {
                                id,
                                conn: Arc::new(conn),
                                opened_at: now,
                                last_active: now,
                                in_flight: 0,
                                answered: false,
                                timeouts: 0,
                                draining_since: None,
                            });
                            Counters::bump(&this.counters.open);
                            Counters::bump(&this.counters.opened);
                            Self::ensure_janitor_locked(this, &mut st);
                            // A new connection can be due before the instant
                            // a running janitor sleeps until.
                            this.wake.notify_one();
                            Ok(())
                        }
                        Err(err) => {
                            st.last_connect_failure = Some(now);
                            Err(err)
                        }
                    };
                    Some((connecting.tx, outcome))
                }
                other => {
                    // Not the connect this task started (it should not
                    // happen): put the real one back and discard this result.
                    st.connecting = other;
                    stale = result.ok();
                    None
                }
            }
        };
        if let Some(conn) = stale {
            this.connector.close(&conn);
        }
        if let Some((tx, outcome)) = notify {
            tx.send_replace(Some(outcome));
        }
    }
}

impl<K: Connector> Drop for Shared<K> {
    fn drop(&mut self) {
        let st = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for entry in st.entries.drain(..) {
            self.connector.close(&entry.conn);
        }
    }
}

/// Publishes a failure for a connect task that is dropped before it
/// reports, so waiters are never stranded and the slot is freed.
struct ConnectGuard<K: Connector> {
    shared: Weak<Shared<K>>,
    epoch: u64,
    armed: bool,
}

impl<K: Connector> Drop for ConnectGuard<K> {
    fn drop(&mut self) {
        if self.armed
            && let Some(shared) = self.shared.upgrade()
        {
            Shared::finish_connect(
                &shared,
                self.epoch,
                Err(Error::Transport(
                    "upstream connection attempt was cancelled".to_string(),
                )),
            );
        }
    }
}

async fn run_connect<K: Connector>(shared: Weak<Shared<K>>, connector: Arc<K>, epoch: u64) {
    let mut guard = ConnectGuard {
        shared: shared.clone(),
        epoch,
        armed: true,
    };
    let hooks = {
        // Not held across the connect: the pool must stay droppable while a
        // connect is in progress.
        let Some(strong) = shared.upgrade() else {
            guard.armed = false;
            return;
        };
        PoolHooks {
            unsolicited: Arc::clone(&strong.counters.unsolicited),
        }
    };
    let result = connector.connect(hooks).await;
    guard.armed = false;
    if let Some(shared) = shared.upgrade() {
        Shared::finish_connect(&shared, epoch, result);
    } else if let Ok(conn) = result {
        connector.close(&conn);
    }
}

async fn run_janitor<K: Connector>(shared: Weak<Shared<K>>, wake: Arc<Notify>) {
    loop {
        let Some(strong) = shared.upgrade() else {
            return;
        };
        let mut closing = Vec::new();
        let deadline = {
            let mut st = lock(&strong.state);
            strong.sweep_locked(&mut st, Instant::now(), &mut closing);
            let next = strong.next_deadline_locked(&st);
            st.janitor_deadline = next;
            if st.entries.is_empty() {
                // Nothing left to watch; the next connect starts a new
                // janitor. Dropping the handle here only flags this task,
                // which returns right below.
                st.janitor = None;
                st.janitor_deadline = None;
                strong.close_all(closing);
                return;
            }
            next
        };
        strong.close_all(closing);
        drop(strong);
        // Connections exist but none has a deadline yet (for example every
        // connection is busy and there is no maximum lifetime): stay alive and
        // sleep until a lease ends or a connection opens, so the connection
        // that becomes idle is still closed at its idle timeout.
        match deadline {
            Some(deadline) => {
                tokio::select! {
                    () = sleep_until(deadline) => {}
                    () = wake.notified() => {}
                }
            }
            None => wake.notified().await,
        }
    }
}

/// One admitted query on one pooled connection.
///
/// Holding a lease reserves one admission permit and one slot on the
/// connection. Dropping it, including when the owning future is cancelled,
/// releases both and records the connection's activity. A lease never
/// outlives the pool it came from by more than the `Arc` it holds.
pub(crate) struct Lease<K: Connector> {
    shared: Arc<Shared<K>>,
    entry_id: u64,
    conn: Arc<K::Conn>,
    /// The connection had answered a query when the lease was granted; only
    /// the tests read it back (the stream engine asks the connection itself
    /// whether it has answered, at the time of the failure).
    #[cfg_attr(not(test), allow(dead_code))]
    reused: bool,
    // Dropped after the slot is released in `Drop::drop`.
    _permit: OwnedSemaphorePermit,
}

impl<K: Connector> Lease<K> {
    /// The leased connection.
    pub(crate) fn conn(&self) -> &Arc<K::Conn> {
        &self.conn
    }

    /// Whether the connection had already answered a query when this lease
    /// was granted.
    #[cfg(test)]
    pub(crate) fn is_reused(&self) -> bool {
        self.reused
    }

    /// Records that the query completed successfully: the connection counts
    /// as having answered, and its consecutive-timeout streak ends.
    pub(crate) fn complete(self) {
        let mut st = lock(&self.shared.state);
        if let Some(entry) = st.entries.iter_mut().find(|e| e.id == self.entry_id) {
            entry.answered = true;
            entry.timeouts = 0;
        }
    }

    /// Records that the query hit its deadline on this connection. Returns
    /// whether that was the last straw: after three consecutive expiries
    /// without a success the connection is retired as half-open.
    pub(crate) fn note_timeout(&self) -> bool {
        let mut closing = Vec::new();
        let dead = {
            let mut st = lock(&self.shared.state);
            match st.entries.iter().position(|e| e.id == self.entry_id) {
                Some(idx) => {
                    st.entries[idx].timeouts += 1;
                    let dead = st.entries[idx].timeouts >= CONSECUTIVE_TIMEOUT_LIMIT;
                    if dead {
                        self.shared
                            .retire(&mut st, idx, CloseReason::Error, &mut closing);
                    }
                    dead
                }
                None => false,
            }
        };
        self.shared.close_all(closing);
        dead
    }

    /// Retires the connection because it failed. It takes no new leases from
    /// now on; leases already on it keep their `Arc` until they end.
    pub(crate) fn mark_dead(&self) {
        let mut closing = Vec::new();
        {
            let mut st = lock(&self.shared.state);
            if let Some(idx) = st.entries.iter().position(|e| e.id == self.entry_id) {
                self.shared
                    .retire(&mut st, idx, CloseReason::Error, &mut closing);
            }
        }
        self.shared.close_all(closing);
    }
}

impl<K: Connector> Drop for Lease<K> {
    fn drop(&mut self) {
        let now = Instant::now();
        let shared = &self.shared;
        let mut closing = Vec::new();
        let mut wake = false;
        {
            let mut st = lock(&shared.state);
            if let Some(idx) = st.entries.iter().position(|e| e.id == self.entry_id) {
                let entry = &mut st.entries[idx];
                entry.in_flight = entry.in_flight.saturating_sub(1);
                entry.last_active = now;
                if entry.in_flight == 0 {
                    if entry.draining_since.is_some() {
                        shared.retire(&mut st, idx, CloseReason::Lifetime, &mut closing);
                    } else {
                        let candidate = after(now, shared.config.idle_timeout_value());
                        wake = match (candidate, st.janitor_deadline) {
                            (Some(c), Some(d)) => c < d,
                            (Some(_), None) => true,
                            (None, _) => false,
                        };
                    }
                }
            }
            Counters::drop_one(&shared.counters.in_flight);
        }
        shared.close_all(closing);
        if wake {
            shared.wake.notify_one();
        }
    }
}

/// A connection pool for one upstream, generic over how connections are
/// opened ([`Connector`]).
///
/// The pool is the owner of every task and connection it creates; dropping it
/// aborts the tasks and closes the connections. Methods that may start a
/// task must be called from inside a Tokio runtime.
pub(crate) struct Pool<K: Connector> {
    shared: Arc<Shared<K>>,
}

impl<K: Connector> Pool<K> {
    /// Creates a pool.
    ///
    /// `drain_grace` is how long a connection past its maximum lifetime may
    /// keep serving its in-flight queries before it is closed regardless; a
    /// transport passes its read timeout. No task is started and no
    /// connection opened until the first [`Pool::acquire`].
    pub(crate) fn new(config: PoolConfig, connector: Arc<K>, drain_grace: Duration) -> Self {
        let admission = Arc::new(Semaphore::new(config.capacity()));
        // A grace longer than the lifetime would let several draining
        // generations pile up, so cap it.
        let drain_grace = config
            .max_lifetime_value()
            .map_or(drain_grace, |lifetime| drain_grace.min(lifetime));
        Pool {
            shared: Arc::new(Shared {
                config,
                drain_grace,
                connector,
                admission,
                state: Mutex::new(State {
                    entries: Vec::new(),
                    next_entry_id: 0,
                    next_epoch: 0,
                    connecting: None,
                    last_connect_failure: None,
                    janitor: None,
                    janitor_deadline: None,
                }),
                counters: Counters::default(),
                wake: Arc::new(Notify::new()),
            }),
        }
    }

    /// A snapshot of the pool's counters.
    pub(crate) fn stats(&self) -> PoolStats {
        self.shared.counters.snapshot()
    }

    /// Counts one query resent on a fresh connection.
    pub(crate) fn record_retry(&self) {
        Counters::bump(&self.shared.counters.retries);
    }

    /// Retires idle, rotated and dead connections now, without waiting for
    /// the janitor.
    pub(crate) fn sweep(&self) {
        let mut closing = Vec::new();
        {
            let mut st = lock(&self.shared.state);
            self.shared
                .sweep_locked(&mut st, Instant::now(), &mut closing);
        }
        self.shared.close_all(closing);
    }

    /// Admits one query and places it on a connection, opening one if
    /// needed, giving up with [`Error::Timeout`] at `deadline`.
    ///
    /// Cancel-safe: dropping the future at any `.await` releases everything
    /// it holds, and a connect it started keeps running for the callers
    /// waiting on it. A connect failure is returned to every caller that was
    /// waiting for it.
    pub(crate) async fn acquire(&self, deadline: Instant) -> Result<Lease<K>> {
        self.acquire_inner(deadline, false).await
    }

    /// Like [`Pool::acquire`], for a retry after a reused connection failed:
    /// prefers a connection that has not answered a query yet, opening one
    /// when the pool has room, so the retry does not land on another
    /// possibly stale connection.
    pub(crate) async fn acquire_fresh(&self, deadline: Instant) -> Result<Lease<K>> {
        self.acquire_inner(deadline, true).await
    }

    async fn acquire_inner(&self, deadline: Instant, fresh: bool) -> Result<Lease<K>> {
        let shared = &self.shared;
        let mut queued = false;
        let permit = match Arc::clone(&shared.admission).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                queued = true;
                Counters::bump(&shared.counters.queued);
                match timeout_at(deadline, Arc::clone(&shared.admission).acquire_owned()).await {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(pool_closed()),
                    Err(_) => return Err(Error::Timeout),
                }
            }
            Err(TryAcquireError::Closed) => return Err(pool_closed()),
        };
        let mut permit = Some(permit);
        loop {
            let now = Instant::now();
            let mut closing = Vec::new();
            let step = {
                let mut st = lock(&shared.state);
                shared.sweep_locked(&mut st, now, &mut closing);
                match shared.pick(&st, now, fresh) {
                    Pick::Use { idx, scale_up } => {
                        if scale_up {
                            Shared::start_connect_locked(shared, &mut st);
                        }
                        let entry = &mut st.entries[idx];
                        entry.in_flight += 1;
                        let reused = entry.answered;
                        Counters::bump(&shared.counters.in_flight);
                        Counters::bump(&shared.counters.queries);
                        if reused {
                            Counters::bump(&shared.counters.reused_queries);
                        }
                        Ok(Lease {
                            shared: Arc::clone(shared),
                            entry_id: entry.id,
                            conn: Arc::clone(&entry.conn),
                            reused,
                            _permit: permit
                                .take()
                                .expect("the admission permit is held until the lease is built"),
                        })
                    }
                    Pick::Wait { start } => {
                        if start {
                            Shared::start_connect_locked(shared, &mut st);
                        }
                        match st.connecting.as_ref() {
                            Some(connecting) => Err(Some(connecting.tx.subscribe())),
                            None => Err(None),
                        }
                    }
                    Pick::Exhausted => Err(None),
                }
            };
            shared.close_all(closing);
            match step {
                Ok(lease) => return Ok(lease),
                Err(Some(rx)) => {
                    if !queued {
                        queued = true;
                        Counters::bump(&shared.counters.queued);
                    }
                    wait_connect(rx, deadline).await?;
                }
                Err(None) => return Err(pool_closed()),
            }
        }
    }
}

fn pool_closed() -> Error {
    Error::Transport("upstream connection pool has no capacity".to_string())
}

async fn wait_connect(mut rx: watch::Receiver<ConnectState>, deadline: Instant) -> Result<()> {
    match timeout_at(deadline, rx.wait_for(Option::is_some)).await {
        Err(_) => Err(Error::Timeout),
        Ok(Err(_)) => Err(Error::Transport(
            "upstream connection attempt was abandoned".to_string(),
        )),
        Ok(Ok(state)) => state.clone().unwrap_or(Ok(())),
    }
}

/// A slot of a [`PendingTable`].
enum Slot<T> {
    /// A query waiting for its answer.
    Pending(T),
    /// A cancelled query whose id is still reserved; the number identifies
    /// the tombstone in the expiry queue.
    Orphan(u64),
}

/// What [`PendingTable::take`] found for an id.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Taken<T> {
    /// The id belonged to a pending query.
    Pending(T),
    /// The id belonged to a cancelled query (its tombstone is consumed): a
    /// late answer that must be dropped, never delivered.
    Orphaned,
    /// The id is not reserved: an unsolicited frame.
    Unknown,
}

/// The per-connection table of queries awaiting an answer, keyed by the wire
/// message id.
///
/// Ids are allocated from a random start, incrementing and skipping every id
/// that is pending or orphaned, so an id is not reused until the counter has
/// wrapped past it. A query that is cancelled or times out becomes an
/// *orphan* (a tombstone) that keeps its id reserved for `tombstone_ttl`, so
/// a late answer to it can be recognised and dropped rather than delivered
/// to a newer query. The table holds at most `capacity` slots, pending and
/// orphaned together; when it is full of tombstones the oldest is evicted
/// for a new query, and when it is full of pending queries registration is
/// refused.
pub(crate) struct PendingTable<T> {
    slots: HashMap<u16, Slot<T>>,
    /// Tombstones in creation order: (id, tombstone number, expiry).
    tombstones: VecDeque<(u16, u64, Instant)>,
    next_id: u16,
    next_tombstone: u64,
    capacity: usize,
    tombstone_ttl: Duration,
}

impl<T> PendingTable<T> {
    /// Creates a table of at most `capacity` slots (at least 1, at most
    /// 65 535) whose tombstones live `tombstone_ttl`, starting the id
    /// counter at a random value.
    pub(crate) fn new(capacity: usize, tombstone_ttl: Duration) -> Self {
        // `RandomState` is keyed from the operating system's entropy, which
        // makes the start unpredictable without a new dependency.
        let start = RandomState::new().hash_one(0_u8) as u16;
        Self::with_start(capacity, tombstone_ttl, start)
    }

    /// Like [`PendingTable::new`] with an explicit first id.
    pub(crate) fn with_start(capacity: usize, tombstone_ttl: Duration, start: u16) -> Self {
        PendingTable {
            slots: HashMap::new(),
            tombstones: VecDeque::new(),
            next_id: start,
            next_tombstone: 0,
            capacity: capacity.clamp(1, MAX_TABLE_CAPACITY),
            tombstone_ttl,
        }
    }

    /// Slots in use, pending and orphaned.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no slot is in use.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Slots holding a pending query.
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.slots
            .values()
            .filter(|s| matches!(s, Slot::Pending(_)))
            .count()
    }

    /// Drops the tombstones that expired at or before `now`.
    pub(crate) fn sweep(&mut self, now: Instant) {
        while let Some(&(id, number, until)) = self.tombstones.front() {
            if until > now {
                break;
            }
            self.tombstones.pop_front();
            if matches!(self.slots.get(&id), Some(Slot::Orphan(n)) if *n == number) {
                self.slots.remove(&id);
            }
        }
    }

    /// Evicts the oldest live tombstone; `false` when there is none.
    fn evict_oldest_tombstone(&mut self) -> bool {
        while let Some((id, number, _)) = self.tombstones.pop_front() {
            if matches!(self.slots.get(&id), Some(Slot::Orphan(n)) if *n == number) {
                self.slots.remove(&id);
                return true;
            }
        }
        false
    }

    /// Reserves a fresh wire id for `value`. Gives `value` back when the
    /// table is full of pending queries.
    ///
    /// The id differs from every pending and orphaned id.
    pub(crate) fn register(&mut self, value: T, now: Instant) -> std::result::Result<u16, T> {
        self.sweep(now);
        if self.slots.len() >= self.capacity && !self.evict_oldest_tombstone() {
            return Err(value);
        }
        // `len < capacity <= 65_535` leaves at least one id free, so the scan
        // terminates.
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if let std::collections::hash_map::Entry::Vacant(slot) = self.slots.entry(id) {
                slot.insert(Slot::Pending(value));
                return Ok(id);
            }
        }
    }

    /// Turns a pending query into a tombstone (it was cancelled or timed
    /// out), returning its value. `None` when `id` is not pending.
    #[cfg(test)]
    pub(crate) fn orphan(&mut self, id: u16, now: Instant) -> Option<T> {
        self.orphan_if(id, now, |_| true)
    }

    /// Like [`PendingTable::orphan`], but only when the pending value passes
    /// `owned`: a guard that outlived its slot (the answer was delivered and
    /// the id was handed out again) must not tombstone someone else's query.
    pub(crate) fn orphan_if(
        &mut self,
        id: u16,
        now: Instant,
        owned: impl FnOnce(&T) -> bool,
    ) -> Option<T> {
        match self.slots.get(&id) {
            Some(Slot::Pending(value)) if owned(value) => {}
            _ => return None,
        }
        let number = self.next_tombstone;
        self.next_tombstone += 1;
        let until = after(now, self.tombstone_ttl).unwrap_or(now);
        match self.slots.insert(id, Slot::Orphan(number)) {
            Some(Slot::Pending(value)) => {
                self.tombstones.push_back((id, number, until));
                Some(value)
            }
            _ => None,
        }
    }

    /// Removes the slot for an answer that arrived with `id`.
    pub(crate) fn take(&mut self, id: u16) -> Taken<T> {
        match self.slots.remove(&id) {
            Some(Slot::Pending(value)) => Taken::Pending(value),
            Some(Slot::Orphan(number)) => {
                // Drop the now-meaningless expiry entry so the queue stays
                // bounded by the slots in use.
                if let Some(pos) = self
                    .tombstones
                    .iter()
                    .position(|&(i, n, _)| i == id && n == number)
                {
                    self.tombstones.remove(pos);
                }
                Taken::Orphaned
            }
            None => Taken::Unknown,
        }
    }

    /// Removes every slot, returning the pending values (the connection is
    /// closing and all its waiters must be failed).
    pub(crate) fn drain_pending(&mut self) -> Vec<T> {
        self.tombstones.clear();
        self.slots
            .drain()
            .filter_map(|(_, slot)| match slot {
                Slot::Pending(value) => Some(value),
                Slot::Orphan(_) => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use super::*;

    // ---- fake connector ---------------------------------------------------

    /// What a test can observe about one fake connection.
    #[derive(Default)]
    struct ConnProbe {
        alive_flag: AtomicBool,
        closed: AtomicBool,
    }

    struct FakeConn {
        probe: Arc<ConnProbe>,
    }

    /// A connector whose connects wait on a gate, can fail, and are counted.
    struct Fake {
        connects: AtomicUsize,
        gate: Semaphore,
        gated: AtomicBool,
        fail: AtomicBool,
        probes: Mutex<Vec<Arc<ConnProbe>>>,
        dropped_connect: Arc<AtomicBool>,
        hang: AtomicBool,
        hooks: Mutex<Vec<PoolHooks>>,
    }

    impl Fake {
        fn new() -> Arc<Self> {
            Arc::new(Fake {
                connects: AtomicUsize::new(0),
                gate: Semaphore::new(0),
                gated: AtomicBool::new(false),
                fail: AtomicBool::new(false),
                probes: Mutex::new(Vec::new()),
                dropped_connect: Arc::new(AtomicBool::new(false)),
                hang: AtomicBool::new(false),
                hooks: Mutex::new(Vec::new()),
            })
        }

        fn gated() -> Arc<Self> {
            let fake = Fake::new();
            fake.gated.store(true, Ordering::SeqCst);
            fake
        }

        fn connects(&self) -> usize {
            self.connects.load(Ordering::SeqCst)
        }

        fn open_gate(&self, n: usize) {
            self.gate.add_permits(n);
        }

        fn probe(&self, i: usize) -> Arc<ConnProbe> {
            Arc::clone(&lock(&self.probes)[i])
        }
    }

    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl Connector for Fake {
        type Conn = FakeConn;

        async fn connect(&self, hooks: PoolHooks) -> Result<FakeConn> {
            lock(&self.hooks).push(hooks);
            let _flag = SetOnDrop(Arc::clone(&self.dropped_connect));
            self.connects.fetch_add(1, Ordering::SeqCst);
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.gated.load(Ordering::SeqCst) {
                self.gate.acquire().await.expect("gate open").forget();
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error::Transport("connect refused".to_string()));
            }
            let probe = Arc::new(ConnProbe::default());
            probe.alive_flag.store(true, Ordering::SeqCst);
            lock(&self.probes).push(Arc::clone(&probe));
            Ok(FakeConn { probe })
        }

        fn is_alive(&self, conn: &FakeConn) -> bool {
            conn.probe.alive_flag.load(Ordering::SeqCst)
        }

        fn close(&self, conn: &FakeConn) {
            conn.probe.closed.store(true, Ordering::SeqCst);
        }
    }

    fn config(connections: usize, in_flight: usize) -> PoolConfig {
        PoolConfig::new()
            .max_connections(connections)
            .max_in_flight(in_flight)
    }

    fn pool_with(config: PoolConfig, fake: &Arc<Fake>) -> Arc<Pool<Fake>> {
        Arc::new(Pool::new(config, Arc::clone(fake), Duration::from_secs(5)))
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    fn permits<K: Connector>(pool: &Pool<K>) -> usize {
        pool.shared.admission.available_permits()
    }

    // ---- configuration ----------------------------------------------------

    #[test]
    fn config_defaults() {
        let c = PoolConfig::new();
        assert!(c.is_enabled());
        assert_eq!(c.max_connections_value(), 4);
        assert_eq!(c.max_in_flight_value(), 64);
        assert_eq!(c.idle_timeout_value(), Duration::from_secs(20));
        assert_eq!(c.max_lifetime_value(), Some(Duration::from_secs(600)));
        assert_eq!(c.capacity(), 256);
        let d = PoolConfig::default();
        assert_eq!(d.capacity(), c.capacity());
        assert!(d.is_enabled());
    }

    #[test]
    fn config_disabled_stays_disabled_through_builders() {
        let c = PoolConfig::disabled();
        assert!(!c.is_enabled());
        let c = c.max_connections(8).max_in_flight(8);
        assert!(!c.is_enabled());
        assert_eq!(c.max_connections_value(), 8);
    }

    #[test]
    fn config_clamps() {
        assert_eq!(PoolConfig::new().max_connections(0).max_connections, 1);
        assert_eq!(PoolConfig::new().max_connections(16).max_connections, 16);
        assert_eq!(PoolConfig::new().max_connections(17).max_connections, 16);
        assert_eq!(
            PoolConfig::new()
                .max_connections(usize::MAX)
                .max_connections,
            16
        );
        assert_eq!(PoolConfig::new().max_in_flight(0).max_in_flight, 1);
        assert_eq!(PoolConfig::new().max_in_flight(256).max_in_flight, 256);
        assert_eq!(PoolConfig::new().max_in_flight(257).max_in_flight, 256);
        assert_eq!(
            PoolConfig::new().max_in_flight(usize::MAX).max_in_flight,
            256
        );
        assert_eq!(
            PoolConfig::new().idle_timeout(Duration::ZERO).idle_timeout,
            Duration::from_secs(1)
        );
        assert_eq!(
            PoolConfig::new()
                .idle_timeout(Duration::from_millis(999))
                .idle_timeout,
            Duration::from_secs(1)
        );
        assert_eq!(
            PoolConfig::new()
                .idle_timeout(Duration::from_secs(90))
                .idle_timeout,
            Duration::from_secs(90)
        );
        assert_eq!(PoolConfig::new().max_lifetime(None).max_lifetime, None);
        assert_eq!(
            PoolConfig::new()
                .max_lifetime(Some(Duration::ZERO))
                .max_lifetime,
            Some(Duration::from_secs(1))
        );
        assert_eq!(config(16, 256).capacity(), 4096);
    }

    #[test]
    fn stats_default_is_all_zero() {
        let s = PoolStats::default();
        assert_eq!(s.connections_open(), 0);
        assert_eq!(s.connections_opened(), 0);
        assert_eq!(s.closed_idle(), 0);
        assert_eq!(s.closed_lifetime(), 0);
        assert_eq!(s.closed_error(), 0);
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.queries(), 0);
        assert_eq!(s.reused_queries(), 0);
        assert_eq!(s.retries(), 0);
        assert_eq!(s.queued(), 0);
        assert_eq!(s.unsolicited(), 0);
    }

    // ---- admission --------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn admission_bounds_leases_and_is_fifo() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 2), &fake);
        let l1 = pool.acquire(deadline()).await.unwrap();
        let l2 = pool.acquire(deadline()).await.unwrap();
        assert_eq!(pool.stats().in_flight(), 2);
        assert_eq!(permits(&pool), 0);

        let order = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for i in 0..3_usize {
            let pool = Arc::clone(&pool);
            let order = Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                let lease = pool.acquire(deadline()).await.unwrap();
                lock(&order).push(i);
                drop(lease);
            }));
            settle().await;
        }
        assert!(lock(&order).is_empty(), "no waiter may pass the bound");
        // The first call waited for the connect, the three above for a slot.
        assert_eq!(pool.stats().queued(), 4);
        assert_eq!(pool.stats().in_flight(), 2);

        drop(l1);
        drop(l2);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(*lock(&order), vec![0, 1, 2]);
        assert_eq!(pool.stats().in_flight(), 0);
        assert_eq!(permits(&pool), 2);
        assert_eq!(fake.connects(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn admission_times_out_at_the_deadline() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 1), &fake);
        let held = pool.acquire(deadline()).await.unwrap();
        let err = pool
            .acquire(Instant::now() + Duration::from_secs(5))
            .await
            .err()
            .unwrap();
        assert_eq!(err, Error::Timeout);
        // The first call waited for the connect, the second for a slot.
        assert_eq!(pool.stats().queued(), 2);
        assert_eq!(permits(&pool), 0);
        drop(held);
        assert_eq!(permits(&pool), 1);
        assert!(pool.acquire(deadline()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_is_never_exceeded_at_the_clamps() {
        let fake = Fake::new();
        let pool = pool_with(config(4, 8), &fake);
        let mut leases = Vec::new();
        for _ in 0..32 {
            leases.push(pool.acquire(deadline()).await.unwrap());
            settle().await;
            let stats = pool.stats();
            assert!(stats.connections_open() <= 4);
            assert!(stats.in_flight() <= 32);
        }
        assert_eq!(pool.stats().in_flight(), 32);
        assert_eq!(pool.stats().connections_open(), 4);
        assert_eq!(fake.connects(), 4);
        assert_eq!(permits(&pool), 0);
        let err = pool
            .acquire(Instant::now() + Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert_eq!(err, Error::Timeout);
        assert_eq!(fake.connects(), 4);
    }

    // ---- connect de-duplication -------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn waiters_share_one_connect() {
        let fake = Fake::gated();
        let pool = pool_with(config(1, 64), &fake);
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let pool = Arc::clone(&pool);
            tasks.push(tokio::spawn(async move { pool.acquire(deadline()).await }));
        }
        settle().await;
        assert_eq!(fake.connects(), 1, "ten waiters, one connect");
        assert_eq!(pool.stats().in_flight(), 0);
        fake.open_gate(1);
        let mut leases = Vec::new();
        for task in tasks {
            leases.push(task.await.unwrap().unwrap());
        }
        assert_eq!(fake.connects(), 1);
        let stats = pool.stats();
        assert_eq!(stats.connections_opened(), 1);
        assert_eq!(stats.in_flight(), 10);
        assert_eq!(stats.queries(), 10);
        assert_eq!(stats.queued(), 10);
        assert!(
            leases
                .iter()
                .all(|l| Arc::ptr_eq(l.conn(), leases[0].conn()))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_failure_fans_out_to_every_waiter() {
        let fake = Fake::gated();
        fake.fail.store(true, Ordering::SeqCst);
        let pool = pool_with(config(1, 64), &fake);
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let pool = Arc::clone(&pool);
            tasks.push(tokio::spawn(async move { pool.acquire(deadline()).await }));
        }
        settle().await;
        fake.open_gate(1);
        for task in tasks {
            let err = task.await.unwrap().err().unwrap();
            assert_eq!(err, Error::Transport("connect refused".to_string()));
        }
        assert_eq!(fake.connects(), 1, "one attempt for the whole round");
        assert_eq!(pool.stats().connections_open(), 0);
        assert_eq!(pool.stats().in_flight(), 0);
        assert_eq!(permits(&pool), 64);

        // The next round tries again and can succeed.
        fake.fail.store(false, Ordering::SeqCst);
        fake.open_gate(1);
        assert!(pool.acquire(deadline()).await.is_ok());
        assert_eq!(fake.connects(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_wait_respects_the_deadline_and_the_connect_survives() {
        let fake = Fake::gated();
        let pool = pool_with(config(1, 4), &fake);
        let err = pool
            .acquire(Instant::now() + Duration::from_secs(2))
            .await
            .err()
            .unwrap();
        assert_eq!(err, Error::Timeout);
        assert_eq!(permits(&pool), 4);
        assert_eq!(fake.connects(), 1);
        // The connect keeps running without its caller and its connection is
        // kept for the next one.
        fake.open_gate(1);
        let lease = pool.acquire(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 1);
        assert_eq!(pool.stats().connections_opened(), 1);
        drop(lease);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_waiter_does_not_disturb_the_others() {
        let fake = Fake::gated();
        let pool = pool_with(config(1, 4), &fake);
        let a = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|_| ()) })
        };
        settle().await;
        let b = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.acquire(deadline()).await })
        };
        settle().await;
        a.abort();
        assert!(a.await.unwrap_err().is_cancelled());
        assert_eq!(
            permits(&pool),
            3,
            "the cancelled waiter released its permit"
        );
        fake.open_gate(1);
        let lease = b.await.unwrap().unwrap();
        assert_eq!(fake.connects(), 1);
        assert_eq!(pool.stats().in_flight(), 1);
        drop(lease);
        assert_eq!(permits(&pool), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_the_connect_leader_does_not_strand_followers() {
        let fake = Fake::gated();
        let pool = pool_with(config(1, 4), &fake);
        let leader = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|_| ()) })
        };
        settle().await;
        let follower = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.acquire(deadline()).await })
        };
        settle().await;
        leader.abort();
        assert!(leader.await.unwrap_err().is_cancelled());
        settle().await;
        assert_eq!(fake.connects(), 1, "the connect outlives the leader");
        fake.open_gate(1);
        let lease = follower.await.unwrap().unwrap();
        assert_eq!(fake.connects(), 1);
        drop(lease);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_pool_cancels_a_connect_in_progress() {
        let fake = Fake::new();
        fake.hang.store(true, Ordering::SeqCst);
        let pool = pool_with(config(1, 4), &fake);
        let waiter = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.acquire(deadline()).await.map(|_| ()) })
        };
        settle().await;
        assert_eq!(fake.connects(), 1);
        assert!(!fake.dropped_connect.load(Ordering::SeqCst));
        waiter.abort();
        let _ = waiter.await;
        drop(pool);
        settle().await;
        assert!(
            fake.dropped_connect.load(Ordering::SeqCst),
            "the connect task is aborted with the pool"
        );
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0
        );
    }

    // ---- choice and scaling -----------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn scales_out_above_the_threshold_without_blocking_the_caller() {
        let fake = Fake::new();
        // Threshold is max(1, 8 / 4) = 2.
        let pool = pool_with(config(4, 8), &fake);
        let l1 = pool.acquire(deadline()).await.unwrap();
        let l2 = pool.acquire(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 1, "below the threshold: no scale-up");
        let l3 = pool.acquire(deadline()).await.unwrap();
        assert!(
            Arc::ptr_eq(l3.conn(), l1.conn()),
            "the caller that triggers scale-up does not wait for it"
        );
        settle().await;
        assert_eq!(fake.connects(), 2);
        let l4 = pool.acquire(deadline()).await.unwrap();
        assert!(!Arc::ptr_eq(l4.conn(), l1.conn()), "least loaded wins");
        assert_eq!(pool.stats().connections_open(), 2);
        drop((l1, l2, l3, l4));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_scale_up_backs_off() {
        let fake = Fake::new();
        // Threshold is max(1, 4 / 4) = 1.
        let pool = pool_with(config(2, 4), &fake);
        let l1 = pool.acquire(deadline()).await.unwrap();
        fake.fail.store(true, Ordering::SeqCst);
        let l2 = pool.acquire(deadline()).await.unwrap();
        settle().await;
        assert_eq!(fake.connects(), 2, "the scale-up attempt failed");
        let l3 = pool.acquire(deadline()).await.unwrap();
        settle().await;
        assert_eq!(fake.connects(), 2, "no new attempt inside the backoff");
        tokio::time::advance(SCALE_RETRY_BACKOFF + Duration::from_millis(1)).await;
        fake.fail.store(false, Ordering::SeqCst);
        let l4 = pool.acquire(deadline()).await.unwrap();
        settle().await;
        assert_eq!(fake.connects(), 3);
        assert_eq!(pool.stats().connections_open(), 2);
        drop((l1, l2, l3, l4));
    }

    #[tokio::test(start_paused = true)]
    async fn one_in_flight_per_connection_opens_up_to_the_connection_limit() {
        let fake = Fake::new();
        let pool = pool_with(config(3, 1), &fake);
        let mut leases = Vec::new();
        for _ in 0..3 {
            leases.push(pool.acquire(deadline()).await.unwrap());
        }
        assert_eq!(pool.stats().connections_open(), 3);
        assert_eq!(fake.connects(), 3);
        let err = pool
            .acquire(Instant::now() + Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert_eq!(err, Error::Timeout);
    }

    // ---- failure and reuse bookkeeping -------------------------------------

    #[tokio::test(start_paused = true)]
    async fn reuse_is_counted_after_a_completed_query() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8), &fake);
        let first = pool.acquire(deadline()).await.unwrap();
        assert!(!first.is_reused());
        first.complete();
        let second = pool.acquire(deadline()).await.unwrap();
        assert!(second.is_reused());
        let stats = pool.stats();
        assert_eq!(stats.queries(), 2);
        assert_eq!(stats.reused_queries(), 1);
        assert_eq!(stats.connections_opened(), 1);
        drop(second);
        // A lease dropped without completing does not count as an answer.
        let third = pool.acquire(deadline()).await.unwrap();
        assert!(
            third.is_reused(),
            "the connection still has its first answer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dead_connection_is_replaced() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8), &fake);
        let lease = pool.acquire(deadline()).await.unwrap();
        lease.mark_dead();
        lease.mark_dead(); // idempotent
        let stats = pool.stats();
        assert_eq!(stats.closed_error(), 1);
        assert_eq!(stats.connections_open(), 0);
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        let next = pool.acquire(deadline()).await.unwrap();
        assert!(!Arc::ptr_eq(next.conn(), lease.conn()));
        assert_eq!(fake.connects(), 2);
        // The old lease still releases cleanly.
        drop(lease);
        assert_eq!(pool.stats().in_flight(), 1);
        drop(next);
        assert_eq!(pool.stats().in_flight(), 0);
        assert_eq!(permits(&pool), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_reported_dead_by_the_connector_is_dropped_at_selection() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8), &fake);
        drop(pool.acquire(deadline()).await.unwrap());
        fake.probe(0).alive_flag.store(false, Ordering::SeqCst);
        let next = pool.acquire(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 2);
        let stats = pool.stats();
        assert_eq!(stats.closed_error(), 1);
        assert_eq!(stats.connections_open(), 1);
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        drop(next);
    }

    #[tokio::test(start_paused = true)]
    async fn three_consecutive_timeouts_retire_the_connection() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8), &fake);
        let lease = pool.acquire(deadline()).await.unwrap();
        assert!(!lease.note_timeout());
        assert!(!lease.note_timeout());
        // A success in between resets the streak.
        let other = pool.acquire(deadline()).await.unwrap();
        other.complete();
        assert!(!lease.note_timeout());
        assert!(!lease.note_timeout());
        assert!(lease.note_timeout(), "third in a row is the last straw");
        assert_eq!(pool.stats().closed_error(), 1);
        assert_eq!(pool.stats().connections_open(), 0);
        assert!(!lease.note_timeout(), "already retired");
    }

    #[tokio::test(start_paused = true)]
    async fn retry_and_unsolicited_counters() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 1), &fake);
        pool.record_retry();
        pool.record_retry();
        // A connection's tasks report through the hooks the connector got.
        pool.acquire(deadline()).await.unwrap().complete();
        lock(&fake.hooks)[0].record_unsolicited();
        assert_eq!(pool.stats().retries(), 2);
        assert_eq!(pool.stats().unsolicited(), 1);
    }

    // ---- idle and lifetime --------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_closed_at_the_idle_timeout() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8).idle_timeout(Duration::from_secs(20)), &fake);
        pool.acquire(deadline()).await.unwrap().complete();
        settle().await;
        tokio::time::advance(Duration::from_secs(19)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        let stats = pool.stats();
        assert_eq!(stats.connections_open(), 0);
        assert_eq!(stats.closed_idle(), 1);
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        // A later query simply opens a new connection.
        pool.acquire(deadline()).await.unwrap().complete();
        assert_eq!(pool.stats().connections_opened(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn activity_defers_the_idle_close_and_a_busy_connection_never_idles() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8).idle_timeout(Duration::from_secs(20)), &fake);
        let busy = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1, "in flight, not idle");
        drop(busy); // idle clock restarts here
        tokio::time::advance(Duration::from_secs(15)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        pool.acquire(deadline()).await.unwrap().complete(); // activity
        tokio::time::advance(Duration::from_secs(15)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1, "idle clock was reset");
        tokio::time::advance(Duration::from_secs(6)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 0);
        assert_eq!(pool.stats().closed_idle(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_lifetime_a_connection_that_turns_idle_after_a_busy_wakeup_is_closed() {
        let fake = Fake::new();
        let pool = pool_with(
            config(1, 8)
                .max_lifetime(None)
                .idle_timeout(Duration::from_secs(20)),
            &fake,
        );
        let busy = pool.acquire(deadline()).await.unwrap();
        // The janitor wakes at the first idle deadline while the connection
        // is busy and finds nothing to schedule.
        tokio::time::advance(Duration::from_secs(25)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        drop(busy);
        tokio::time::advance(Duration::from_secs(19)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 0);
        assert_eq!(pool.stats().closed_idle(), 1);
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn activity_defers_the_idle_close_without_a_lifetime() {
        let fake = Fake::new();
        let pool = pool_with(
            config(1, 8)
                .max_lifetime(None)
                .idle_timeout(Duration::from_secs(20)),
            &fake,
        );
        let busy = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1, "in flight, not idle");
        drop(busy);
        tokio::time::advance(Duration::from_secs(15)).await;
        settle().await;
        pool.acquire(deadline()).await.unwrap().complete();
        tokio::time::advance(Duration::from_secs(15)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        tokio::time::advance(Duration::from_secs(6)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 0);
        assert_eq!(pool.stats().closed_idle(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_idle_connection_is_not_held_open_by_a_busy_one() {
        let fake = Fake::new();
        // Threshold is 1, so the second lease triggers a second connection.
        let pool = pool_with(
            config(2, 4)
                .max_lifetime(None)
                .idle_timeout(Duration::from_secs(20)),
            &fake,
        );
        let l1 = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        let l2 = pool.acquire(deadline()).await.unwrap(); // scale-up starts
        drop(l2);
        settle().await;
        assert_eq!(pool.stats().connections_open(), 2);
        // The second connection went idle at t=10 and is due at t=30 while
        // the first stays busy.
        tokio::time::advance(Duration::from_secs(21)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        assert_eq!(pool.stats().closed_idle(), 1);
        drop(l1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_idle_connection_is_closed_on_time_while_the_janitor_sleeps_on_a_long_lifetime() {
        let fake = Fake::new();
        // The first connection's lifetime deadline is 600 s away, so the
        // janitor sleeps until then unless a new connection wakes it.
        let pool = pool_with(
            config(2, 4)
                .max_lifetime(Some(Duration::from_secs(600)))
                .idle_timeout(Duration::from_secs(20)),
            &fake,
        );
        let l1 = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        let l2 = pool.acquire(deadline()).await.unwrap(); // scale-up starts
        drop(l2);
        settle().await;
        assert_eq!(pool.stats().connections_open(), 2);
        // The second connection went idle at t=10 and is due at t=30 while
        // the first stays busy and the janitor's own deadline is t=600.
        tokio::time::advance(Duration::from_secs(21)).await;
        settle().await;
        let stats = pool.stats();
        assert_eq!(stats.connections_open(), 1);
        assert_eq!(stats.closed_idle(), 1);
        drop(l1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_acquire_opens_a_new_connection_when_every_one_has_answered() {
        let fake = Fake::new();
        let pool = pool_with(config(2, 4), &fake);
        pool.acquire(deadline()).await.unwrap().complete();
        let lease = pool.acquire_fresh(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 2);
        assert!(
            !lease.is_reused(),
            "the new connection has answered nothing"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_acquire_falls_back_to_the_least_loaded_connection_when_the_pool_is_full() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 4), &fake);
        pool.acquire(deadline()).await.unwrap().complete();
        let lease = pool.acquire_fresh(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 1);
        assert!(lease.is_reused());
    }

    #[tokio::test(start_paused = true)]
    async fn a_fresh_acquire_reuses_a_connection_that_has_not_answered_yet() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 4), &fake);
        let first = pool.acquire(deadline()).await.unwrap();
        let second = pool.acquire_fresh(deadline()).await.unwrap();
        assert_eq!(fake.connects(), 1);
        assert!(!second.is_reused());
        drop((first, second));
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_grace_is_capped_by_the_lifetime() {
        let fake = Fake::new();
        // Grace 5 s, lifetime 2 s: the hard close comes 2 s after draining.
        let pool = pool_with(
            config(1, 8).max_lifetime(Some(Duration::from_secs(2))),
            &fake,
        );
        let held = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_millis(2100)).await;
        settle().await;
        assert!(!fake.probe(0).closed.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_millis(2000)).await;
        settle().await;
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn an_old_connection_drains_and_a_new_one_takes_over() {
        let fake = Fake::new();
        let pool = pool_with(
            config(1, 8).max_lifetime(Some(Duration::from_secs(60))),
            &fake,
        );
        let old = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(61)).await;
        settle().await;
        // Past its lifetime: still open for its in-flight query, but taking
        // no new ones.
        assert_eq!(pool.stats().connections_open(), 1);
        let next = pool.acquire(deadline()).await.unwrap();
        assert!(!Arc::ptr_eq(next.conn(), old.conn()));
        assert_eq!(pool.stats().connections_open(), 2);
        assert_eq!(fake.connects(), 2);
        drop(old);
        let stats = pool.stats();
        assert_eq!(stats.closed_lifetime(), 1);
        assert_eq!(stats.connections_open(), 1);
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        assert!(!fake.probe(1).closed.load(Ordering::SeqCst));
        drop(next);
    }

    #[tokio::test(start_paused = true)]
    async fn a_draining_connection_is_hard_closed_after_the_grace_period() {
        let fake = Fake::new();
        let pool = pool_with(
            config(1, 8).max_lifetime(Some(Duration::from_secs(60))),
            &fake,
        );
        let held = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(61)).await;
        settle().await;
        assert!(!fake.probe(0).closed.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_secs(5)).await; // grace is 5 s
        settle().await;
        assert!(fake.probe(0).closed.load(Ordering::SeqCst));
        assert_eq!(pool.stats().closed_lifetime(), 1);
        assert_eq!(pool.stats().connections_open(), 0);
        // The lease that outlived its connection still releases cleanly.
        assert_eq!(pool.stats().in_flight(), 1);
        drop(held);
        assert_eq!(pool.stats().in_flight(), 0);
        assert_eq!(pool.stats().closed_lifetime(), 1);
        assert_eq!(permits(&pool), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_lifetime_a_connection_is_never_rotated() {
        let fake = Fake::new();
        let pool = pool_with(
            config(1, 8)
                .max_lifetime(None)
                .idle_timeout(Duration::from_secs(3600)),
            &fake,
        );
        let busy = pool.acquire(deadline()).await.unwrap();
        tokio::time::advance(Duration::from_secs(3000)).await;
        settle().await;
        assert_eq!(pool.stats().connections_open(), 1);
        let again = pool.acquire(deadline()).await.unwrap();
        assert!(Arc::ptr_eq(again.conn(), busy.conn()));
        assert_eq!(pool.stats().closed_lifetime(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_applies_the_policy_immediately() {
        let fake = Fake::new();
        let pool = pool_with(config(1, 8), &fake);
        pool.acquire(deadline()).await.unwrap().complete();
        fake.probe(0).alive_flag.store(false, Ordering::SeqCst);
        pool.sweep();
        assert_eq!(pool.stats().connections_open(), 0);
        assert_eq!(pool.stats().closed_error(), 1);
    }

    // ---- ownership ----------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn dropping_the_pool_closes_connections_and_ends_every_task() {
        let fake = Fake::new();
        let pool = pool_with(config(2, 8), &fake);
        let l1 = pool.acquire(deadline()).await.unwrap();
        let l2 = pool.acquire(deadline()).await.unwrap();
        drop((l1, l2));
        settle().await;
        assert!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks()
                >= 1,
            "the janitor is running"
        );
        let probe = fake.probe(0);
        assert!(!probe.closed.load(Ordering::SeqCst));
        drop(pool);
        settle().await;
        assert!(probe.closed.load(Ordering::SeqCst));
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0
        );
    }

    // ---- pending table ----------------------------------------------------

    fn table(capacity: usize, start: u16) -> PendingTable<&'static str> {
        PendingTable::with_start(capacity, Duration::from_secs(5), start)
    }

    #[tokio::test(start_paused = true)]
    async fn ids_are_unique_and_sequential_from_the_start() {
        let mut t = table(8, 100);
        let now = Instant::now();
        let ids: Vec<u16> = (0..8).map(|_| t.register("q", now).unwrap()).collect();
        assert_eq!(ids, (100..108).collect::<Vec<u16>>());
        assert_eq!(t.len(), 8);
        assert_eq!(t.pending_len(), 8);
    }

    #[tokio::test(start_paused = true)]
    async fn random_start_stays_inside_the_id_space_and_allocates_unique_ids() {
        for _ in 0..16 {
            let mut t = PendingTable::new(64, Duration::from_secs(5));
            let now = Instant::now();
            let ids: std::collections::HashSet<u16> =
                (0..64).map(|_| t.register((), now).unwrap()).collect();
            assert_eq!(ids.len(), 64);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ids_wrap_around_and_skip_reserved_ids() {
        let mut t = table(4, u16::MAX - 1);
        let now = Instant::now();
        assert_eq!(t.register("a", now), Ok(u16::MAX - 1));
        assert_eq!(t.register("b", now), Ok(u16::MAX));
        assert_eq!(t.register("c", now), Ok(0));
        assert_eq!(t.register("d", now), Ok(1));
        assert_eq!(t.register("e", now), Err("e"), "full of pending queries");
        // Put the counter back onto reserved ids: they are skipped.
        assert_eq!(t.take(u16::MAX), Taken::Pending("b"));
        t.next_id = u16::MAX - 1;
        assert_eq!(t.register("f", now), Ok(u16::MAX));
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_table_refuses_new_queries_and_gives_the_value_back() {
        let mut t = table(2, 0);
        let now = Instant::now();
        t.register("a", now).unwrap();
        t.register("b", now).unwrap();
        assert_eq!(t.register("c", now), Err("c"));
        assert_eq!(t.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn take_distinguishes_pending_orphaned_and_unknown() {
        let mut t = table(8, 10);
        let now = Instant::now();
        let a = t.register("a", now).unwrap();
        let b = t.register("b", now).unwrap();
        assert_eq!(t.orphan(b, now), Some("b"));
        assert_eq!(t.orphan(b, now), None, "already orphaned");
        assert_eq!(t.orphan(99, now), None, "never registered");
        assert_eq!(t.pending_len(), 1);
        assert_eq!(t.len(), 2);
        assert_eq!(t.take(a), Taken::Pending("a"));
        assert_eq!(t.take(a), Taken::Unknown, "answered once");
        assert_eq!(
            t.take(b),
            Taken::Orphaned,
            "late answer to a cancelled query"
        );
        assert!(
            t.tombstones.is_empty(),
            "a consumed tombstone leaves the queue"
        );
        assert_eq!(t.take(b), Taken::Unknown, "the tombstone is consumed");
        assert!(t.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_tombstoned_id_is_not_reused_until_the_counter_wraps_or_it_expires() {
        let mut t = table(4, 0);
        let now = Instant::now();
        let a = t.register("a", now).unwrap();
        assert_eq!(t.orphan(a, now), Some("a"));
        // Fill the rest and wrap the counter back onto the tombstone.
        t.next_id = a;
        let fresh = t.register("b", now).unwrap();
        assert_ne!(fresh, a, "the reserved id is skipped");
        // After the tombstone expires the id becomes allocatable again.
        tokio::time::advance(Duration::from_secs(6)).await;
        t.next_id = a;
        assert_eq!(t.register("c", Instant::now()), Ok(a));
    }

    #[tokio::test(start_paused = true)]
    async fn tombstones_are_swept_after_their_ttl() {
        let mut t = table(8, 0);
        let now = Instant::now();
        for _ in 0..3 {
            let id = t.register("q", now).unwrap();
            t.orphan(id, now);
        }
        assert_eq!(t.len(), 3);
        tokio::time::advance(Duration::from_secs(4)).await;
        t.sweep(Instant::now());
        assert_eq!(t.len(), 3, "not yet expired");
        tokio::time::advance(Duration::from_secs(1)).await;
        t.sweep(Instant::now());
        assert_eq!(t.len(), 0);
        // Registration sweeps lazily too.
        let id = t.register("q", Instant::now()).unwrap();
        t.orphan(id, Instant::now());
        tokio::time::advance(Duration::from_secs(5)).await;
        t.register("r", Instant::now()).unwrap();
        assert_eq!(t.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_table_evicts_the_oldest_tombstone_for_a_new_query() {
        let mut t = table(3, 0);
        let now = Instant::now();
        let a = t.register("a", now).unwrap();
        let b = t.register("b", now).unwrap();
        let c = t.register("c", now).unwrap();
        t.orphan(a, now);
        t.orphan(b, now);
        // Full (one pending, two tombstones): the oldest tombstone makes room.
        let d = t.register("d", now).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.take(a), Taken::Unknown, "oldest tombstone was evicted");
        assert_eq!(t.take(b), Taken::Orphaned, "newer tombstone survives");
        assert_eq!(t.take(c), Taken::Pending("c"));
        assert_eq!(t.take(d), Taken::Pending("d"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_consumed_tombstone_does_not_expire_a_newer_one_for_the_same_id() {
        let mut t = table(4, 7);
        let now = Instant::now();
        let id = t.register("a", now).unwrap();
        t.orphan(id, now);
        assert_eq!(t.take(id), Taken::Orphaned);
        // The same id again, orphaned later: its own tombstone must outlive
        // the stale queue entry of the first one.
        t.next_id = id;
        assert_eq!(t.register("b", now), Ok(id));
        tokio::time::advance(Duration::from_secs(3)).await;
        let later = Instant::now();
        t.orphan(id, later);
        tokio::time::advance(Duration::from_secs(3)).await; // first expiry passed
        t.sweep(Instant::now());
        assert_eq!(t.take(id), Taken::Orphaned);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_pending_returns_pending_values_and_clears_the_table() {
        let mut t = table(8, 0);
        let now = Instant::now();
        let a = t.register("a", now).unwrap();
        t.register("b", now).unwrap();
        t.orphan(a, now);
        let mut drained = t.drain_pending();
        drained.sort_unstable();
        assert_eq!(drained, vec!["b"]);
        assert!(t.is_empty());
        assert_eq!(t.take(a), Taken::Unknown);
    }

    #[test]
    fn table_capacity_is_clamped_to_the_id_space() {
        let t: PendingTable<()> = PendingTable::with_start(usize::MAX, Duration::ZERO, 0);
        assert_eq!(t.capacity, 65_535);
        let t: PendingTable<()> = PendingTable::with_start(0, Duration::ZERO, 0);
        assert_eq!(t.capacity, 1);
    }
}
