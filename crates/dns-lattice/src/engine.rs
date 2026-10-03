//! Query orchestration for decoded DNS messages.
//!
//! [`Resolver`] accepts a decoded [`Message`], selects an upstream group by
//! static [`SplitDnsPolicy`] routing, reads and writes its in-memory
//! TTL/negative cache, and invokes registered [`crate::upstream::UpstreamBackend`]
//! values in registration order with retryable-error failover.
//!
//! It does **not** own inbound server lifecycle, socket binding, wire
//! framing, TLS/HTTP/QUIC protocol handling, operating-system DNS
//! configuration, or packet forwarding. Those responsibilities belong
//! respectively to [`crate::server`], [`crate::upstream`], and composing
//! applications. An optional [`crate::hooks::RouteHook`] selects an existing
//! upstream group; it does not own resolution or side effects. When
//! explicitly configured with a
//! [`crate::fakeip::FakeIpPool`] and [`crate::fakeip::FakeIpPolicy`], it does
//! orchestrate their local DNS answer synthesis; allocation and mapping
//! storage remain owned by the pool.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{
    Class, Edns, EdnsOption, Message, Name, Opcode, RData, Rcode, RecordType, ResourceRecord,
    SplitDnsPolicy, UpstreamGroupId,
};
use tokio::runtime::Handle;
use tokio::task::JoinSet;

use crate::cache::TtlPolicy;
use crate::cache::flight::{Flights, Follower, Join, LeaderGuard, Outcome, Wait};
use crate::cache::store::{CachedAnswer, KeyBuf, Store};
use crate::cache::{CacheConfig, CacheStats, FailureCache, Prefetch, ServeStale};
use crate::fakeip::{FakeIpPolicy, FakeIpPool};
use crate::hooks::{RouteDecision, RouteHook, RouteRequest};
use crate::observability::{
    CacheEvent, HookObserveDecision, ObservabilitySink, ObserveEvent, ObserveFailure,
    UpstreamObserveOutcome,
};
use crate::upstream::{DEFAULT_EDNS_UDP_PAYLOAD_SIZE, UpstreamBackend};

/// The `TYPE` value of the EDNS(0) OPT pseudo-record (RFC 6891). Its `TTL`
/// field holds the extended RCODE, version and flags, so it is never
/// clamped, counted down, or used to compute a cache lifetime.
const OPT_RTYPE: u16 = 41;

/// A source of the current time, abstracted so tests can advance it
/// deterministically instead of relying on real `sleep`.
///
/// Crate-private: no external caller needs to inject a clock in this stage;
/// [`Resolver::builder`] always defaults to [`SystemClock`].
pub(crate) trait Clock {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// Production [`Clock`] delegating to [`Instant::now`].
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A manually-advanced [`Clock`] for deterministic tests.
///
/// Interior-mutable and cheaply cloneable (shares the same underlying cell
/// via `Arc<Mutex<_>>`, kept `Send + Sync` so it satisfies
/// [`ResolverBuilder::clock`]'s bound) so a test can keep a handle to
/// advance the clock after handing an owned copy to the resolver.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FakeClock(std::sync::Arc<std::sync::Mutex<Instant>>);

#[cfg(test)]
impl FakeClock {
    /// Starts the clock at the current real instant (only used as an
    /// arbitrary, non-real-time-dependent base point).
    pub(crate) fn new() -> Self {
        FakeClock(std::sync::Arc::new(std::sync::Mutex::new(Instant::now())))
    }

    /// Advances the clock by `duration`.
    pub(crate) fn advance(&self, duration: Duration) {
        let mut guard = self.0.lock().expect("fake clock mutex poisoned");
        *guard += duration;
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().expect("fake clock mutex poisoned")
    }
}

/// An in-process DNS query orchestrator.
///
/// Construct it from a split-DNS policy and one or more upstream backends
/// per group, then resolve decoded queries against it. It owns policy
/// selection, caching, and upstream failover, but not server lifecycle or
/// transport protocol implementation; see the [module documentation].
///
/// [module documentation]: self
///
/// # Lifecycle
///
/// Construct via [`Resolver::builder`], call [`Resolver::resolve`] as many
/// times as needed, then drop. The resolver itself spawns no threads and no
/// tasks unless [`CacheConfig::prefetch`] is configured (a cache hit may
/// start a background refresh on the Tokio runtime it runs in) or
/// serve-stale has a
/// [`client_timeout`](crate::cache::ServeStale::client_timeout) (a query on
/// an expired answer hands its refresh to a background task). A registered
/// [`crate::upstream::TcpBackend`], DoT or DoH backend keeps pooled
/// connections and spawns tasks for them on the runtime that first used it, so
/// the resolver then has to stay on one Tokio runtime (see
/// [`PoolConfig::disabled`](crate::upstream::PoolConfig::disabled)). There is
/// no explicit `shutdown` method — dropping the resolver aborts every refresh
/// still running, and Rust's ordinary drop semantics release everything else
/// it owns, including the pooled connections of its backends and any socket
/// a [`crate::upstream::UdpBackend`] opens per call.
pub struct Resolver {
    inner: Arc<ResolverInner>,
    /// Background refresh tasks; dropping the set aborts them.
    background: Mutex<JoinSet<()>>,
}

/// The resolver state shared with background refresh tasks.
struct ResolverInner {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Vec<Box<dyn UpstreamBackend>>>,
    /// A dense index per registered group, fixed at build time; part of the
    /// cache key so it holds no string.
    group_index: HashMap<UpstreamGroupId, u32>,
    clock: Box<dyn Clock + Send + Sync>,
    /// The bounded answer store; `None` when the cache is disabled.
    cache: Option<Store>,
    ttl_policy: TtlPolicy,
    /// In-flight query registry; `None` when coalescing is off.
    flights: Option<Arc<Flights>>,
    /// Bumped whenever cached content is invalidated; a leader stores its
    /// answer only if the epoch is unchanged since its upstream call began.
    cache_epoch: AtomicU64,
    /// Opt-in prefetch policy.
    prefetch: Option<Prefetch>,
    /// Opt-in serve-stale policy.
    serve_stale: Option<ServeStale>,
    /// Opt-in upstream failure caching; always `None` without a store.
    failure_cache: Option<FailureCache>,
    /// Lookup outcome counters behind [`Resolver::cache_stats`].
    counters: QueryCounters,
    fake_ip: Option<FakeIpResolverConfig>,
    route_hook: Option<Box<dyn RouteHook>>,
    observability_sink: Option<Arc<dyn ObservabilitySink>>,
    next_correlation_id: AtomicU64,
}

/// Cache lookup outcomes counted by the resolver itself (the store counts
/// its own inserts, evictions and expirations).
#[derive(Default)]
struct QueryCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    coalesced: AtomicU64,
    refreshes: AtomicU64,
    stale_hits: AtomicU64,
    failure_hits: AtomicU64,
}

/// The most background refreshes running at once; a hit that would start
/// another is served without one.
const MAX_REFRESH_TASKS: usize = 256;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Explicit Fake IP answer synthesis owned by a [`Resolver`].
///
/// The pool remains caller-owned through [`Arc`], allowing the composing
/// application to perform lookups and retain mappings independently of this
/// resolver. This configuration is deliberately opt-in.
struct FakeIpResolverConfig {
    pool: Arc<FakeIpPool>,
    policy: FakeIpPolicy,
}

impl Resolver {
    /// Starts building a resolver from a split-DNS policy.
    pub fn builder(policy: SplitDnsPolicy) -> ResolverBuilder {
        ResolverBuilder {
            policy,
            backends: HashMap::new(),
            clock: Box::new(SystemClock),
            cache: CacheConfig::new(),
            fake_ip: None,
            route_hook: None,
            observability_sink: None,
        }
    }

    /// Resolves one query.
    ///
    /// Extracts the queried name from `query`'s first question. Locally
    /// handled Fake IP questions return before the hook, cache, and upstream
    /// stages. For every other question, static [`SplitDnsPolicy`] routing
    /// supplies a tentative group and an optional [`crate::hooks::RouteHook`]
    /// can authoritatively replace it. The selected registered group scopes
    /// the in-memory answer cache; on a miss its backends are tried in
    /// registration order: the first
    /// backend to return `Ok` wins and its answer is
    /// cached (per the rules below) and returned immediately. A
    /// backend failing with [`Error::Timeout`], [`Error::Transport`], or
    /// [`Error::Tls`] is treated as retryable — resolution moves on to the
    /// next backend in the group rather than failing the whole call. Once
    /// every backend in the group has been tried and failed, the *last*
    /// attempted backend's error is propagated as-is; this exhausted-group
    /// failure is never cached. A group with exactly one backend behaves
    /// exactly as before: success or that one backend's own error.
    ///
    /// # Cache
    ///
    /// A query uses the cache only when it has exactly one question, opcode
    /// `QUERY`, and an EDNS OPT record (if any) whose options are limited to
    /// NSID, COOKIE, TCP keepalive and Padding; a query carrying EDNS Client
    /// Subnet or any other option, like any other query, goes straight to the
    /// upstream group (reported as a cache miss), is never coalesced, and its
    /// answer is not stored, so a client-specific answer is never shared. The
    /// cache
    /// identity is the question's name (case-insensitively), type and class,
    /// the effective upstream group, the query's RD bit, and the DO bit of
    /// the query's EDNS OPT record (false without a well-formed OPT).
    ///
    /// The cache is a sharded store bounded by [`CacheConfig::max_bytes`]
    /// (16 MiB, estimated, by default). Every insert evicts as much as it
    /// needs to stay within the bound — expired entries first, then entries
    /// that were never reused — so memory use stays bounded however many
    /// distinct names are queried; an answer too large for its shard is
    /// returned but not stored. [`CacheConfig::disabled`] keeps nothing. The
    /// TTL limits below are the defaults of [`CacheConfig`] and can be
    /// changed through [`ResolverBuilder::cache`].
    ///
    /// An answer is stored only when its opcode is `QUERY`, `TC` is clear,
    /// it carries either no EDNS OPT record or a well-formed one whose
    /// extended RCODE is 0, and it is either positive (`NOERROR` with at
    /// least one answer record) or negative (`NXDOMAIN`, or `NOERROR` with an
    /// empty answer section). `SERVFAIL`, `REFUSED` and every other response
    /// code are returned but never stored. The stored copy never keeps the
    /// EDNS OPT record. Before storing, every other record TTL is clamped
    /// into [`CacheConfig::positive_ttl`] (by default at most 86 400 s) for a
    /// positive answer or [`CacheConfig::negative_ttl`] (by default at most
    /// 3 600 s) for a negative one. The entry then lives for:
    ///
    /// - positive: the minimum record TTL over the answer, authority and
    ///   additional sections;
    /// - negative with an SOA in the authority section: min(SOA TTL, SOA
    ///   `MINIMUM`) (RFC 2308 §5), to which the stored SOA's TTL is
    ///   rewritten, or less if another record's TTL is lower;
    /// - negative without an SOA: [`CacheConfig::negative_ttl_without_soa`]
    ///   (60 s by default; such an answer is not stored when it is `None`),
    ///   or less if a record's TTL is lower.
    ///
    /// An answer whose lifetime works out to 0 s is not stored. The lifetime
    /// is measured from the moment the query was received, before the
    /// upstream call.
    ///
    /// A hit returns the stored answer in its original record order with
    /// every TTL reduced by the whole seconds elapsed since it was stored
    /// (never below 1 while it is fresh), the current query's message id,
    /// question section and RD bit, and AA cleared. The entry is a miss from
    /// the instant its lifetime ends and is removed when such a lookup finds
    /// it.
    ///
    /// # Coalescing
    ///
    /// Unless [`CacheConfig::coalesce`] turns it off, concurrent misses for
    /// the same cache identity share one upstream query. The first caller (the
    /// leader) re-checks the cache, queries the group, stores the answer and
    /// only then hands its result to the others (followers). A follower
    /// receives the leader's answer rebuilt like a cache hit (its own message
    /// id, question and RD bit, AA cleared), or the leader's error. It emits
    /// `QueryReceived`, `StaticRoute`, the optional `HookDecision`,
    /// `CacheMiss`, a [`CacheEvent::Coalesced`] through
    /// [`ObservabilitySink::record_cache`], and the terminal event, but no
    /// `UpstreamAttempt` or `UpstreamOutcome`. If the leader's `resolve`
    /// future is dropped, one follower takes over as the new leader; nothing
    /// is spawned, so this works on any executor.
    ///
    /// # Prefetch
    ///
    /// Only when [`CacheConfig::prefetch`] is configured, a fresh cache hit on
    /// a popular entry close to its expiry also starts a background refresh
    /// of that entry on the current Tokio runtime (a hit outside a runtime
    /// starts none). The hit itself is answered from the cache exactly as
    /// above; the refresh is aborted if the resolver is dropped. See
    /// [`crate::cache::Prefetch`].
    ///
    /// # Serve-stale
    ///
    /// Only when [`CacheConfig::serve_stale`] is configured, an expired
    /// answer is kept for the configured window. A query that finds one asks
    /// the upstream first; if that fails (every backend failed, or the answer
    /// is `SERVFAIL`/`REFUSED`) it is answered from the expired entry with a
    /// short TTL and, for an EDNS client, Extended DNS Error 3, and emits
    /// [`CacheEvent::StaleServed`].
    /// Further queries within the recheck window are answered stale without an
    /// upstream call. With a client timeout, a query that waits longer is
    /// answered stale while the refresh continues in a background task. See
    /// [`crate::cache::ServeStale`].
    ///
    /// # Failure caching
    ///
    /// Only when [`CacheConfig::failure_cache`] is configured, a failed
    /// resolution (an error, or a `SERVFAIL`/`REFUSED` answer) is remembered
    /// per cache identity for a short, exponentially growing backoff; queries
    /// inside it get the same error or answer (with their own id) without an
    /// upstream call, and emit
    /// [`CacheEvent::FailureServed`].
    /// A usable stale answer takes precedence over a remembered failure. See
    /// [`crate::cache::FailureCache`].
    ///
    /// # EDNS(0)
    ///
    /// Every `Ok` answer — Fake IP, cache hit, or fresh upstream — is aligned
    /// with the query's EDNS OPT record (RFC 6891):
    ///
    /// - a query without an OPT record gets an answer without one, even when
    ///   the upstream answer carried one;
    /// - a query with a well-formed OPT record gets an answer with exactly one:
    ///   a fresh upstream answer's own well-formed OPT is kept as is;
    ///   otherwise (a cache hit, a Fake IP answer, or an upstream answer
    ///   without a usable OPT) a fresh OPT advertising 1232 bytes, version 0,
    ///   the query's DO bit and no options is attached;
    /// - a query whose OPT record is malformed gets the answer unchanged.
    ///
    /// A cache hit therefore never replays an earlier transaction's OPT
    /// record or its options.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRoute`] when no split-DNS rule matches the queried
    /// name and no default upstream group is configured, when no question is
    /// present in `query`, or when the selected group has no backend
    /// registered. A hook-selected unknown or empty group never falls back to
    /// static policy. A hook failure returns [`Error::Hook`] and is neither
    /// retried nor cached. Returns the last attempted backend's error,
    /// propagated as-is (not cached), once every backend in the matched
    /// group has failed.
    ///
    /// # Runtime requirement
    ///
    /// Must be called from inside a `tokio` runtime context if the selected
    /// backend performs real socket I/O (e.g. [`crate::upstream::UdpBackend`]/
    /// [`crate::upstream::TcpBackend`]) — see `crate::upstream`'s
    /// module-level docs.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        self.inner.resolve(query, &self.background).await
    }

    /// Removes every cached answer and returns how many were removed.
    ///
    /// Use it when the upstream data is known to have changed wholesale (a
    /// network switch, a VPN toggle, a policy reload). Queries already waiting
    /// on an upstream call still receive that call's result, but the result
    /// is not stored: an answer fetched before the flush never outlives it.
    /// The lifetime counters of [`Resolver::cache_stats`] are not reset.
    ///
    /// Takes one shard lock at a time, never across an await, and runs no
    /// callback. With the store disabled it returns 0.
    pub fn clear_cache(&self) -> usize {
        self.inner.clear_cache()
    }

    /// Removes the cached answers for exactly `name` and returns how many
    /// were removed.
    ///
    /// Every upstream group, class and query shape (RD and DO bits) is
    /// covered, and so is every answer kind (positive and negative). With
    /// `rtype` set only that record type is removed; with `None` every type
    /// is. The name is compared case-insensitively. Answers for names below
    /// `name` are kept; see [`Resolver::purge_subtree`].
    ///
    /// Like [`Resolver::clear_cache`], it also stops in-flight queries from
    /// storing the answer they were fetching (for any name: a purge
    /// invalidates every upstream call that began before it).
    pub fn purge(&self, name: &Name, rtype: Option<RecordType>) -> usize {
        self.inner.purge(name, rtype)
    }

    /// Removes the cached answers for `zone` and every name below it, and
    /// returns how many were removed.
    ///
    /// Matching respects label boundaries: purging `ample.com` removes
    /// `ample.com` and `www.ample.com` but not `example.com`. Purging the
    /// root name removes everything, like [`Resolver::clear_cache`] (except
    /// that remembered eviction hashes are kept). The group, class, type and
    /// query shape of an answer do not matter. In-flight queries are handled
    /// as in [`Resolver::purge`].
    pub fn purge_subtree(&self, zone: &Name) -> usize {
        self.inner.purge_subtree(zone)
    }

    /// A snapshot of the cache counters and size. See [`CacheStats`].
    pub fn cache_stats(&self) -> CacheStats {
        self.inner.cache_stats()
    }
}

impl ResolverInner {
    /// The body of [`Resolver::resolve`].
    async fn resolve(
        self: &Arc<Self>,
        query: &Message,
        background: &Mutex<JoinSet<()>>,
    ) -> Result<Message> {
        let correlation_id = self.next_correlation_id.fetch_add(1, Ordering::Relaxed);
        let question = query.questions.first();
        self.emit(ObserveEvent::QueryReceived {
            correlation_id,
            name: question.map(|question| question.name.clone()),
            rtype: question.map(|question| question.qtype),
            class: question.map(|question| question.qclass),
        });
        let Some(question) = query.questions.first() else {
            self.emit(ObserveEvent::Failed {
                correlation_id,
                failure: ObserveFailure::NoRoute,
            });
            return Err(Error::NoRoute);
        };
        if let Some(fake_ip) = &self.fake_ip {
            match fake_ip_answer(query, fake_ip) {
                Ok(Some(mut answer)) => {
                    align_edns(query, &mut answer);
                    self.emit(ObserveEvent::FakeIpTerminal { correlation_id });
                    self.emit(ObserveEvent::Completed {
                        correlation_id,
                        rcode: answer.header.rcode,
                    });
                    return Ok(answer);
                }
                Ok(None) => {}
                Err(error) => {
                    self.emit(ObserveEvent::Failed {
                        correlation_id,
                        failure: observe_failure(&error),
                    });
                    return Err(error);
                }
            }
        }

        let (group, group_index, backends) =
            match self.select_backends(question, correlation_id).await {
                Ok(selected) => selected,
                Err(error) => {
                    self.emit(ObserveEvent::Failed {
                        correlation_id,
                        failure: observe_failure(&error),
                    });
                    return Err(error);
                }
            };
        // The canonical key is built once, on the stack, and hashed once; the
        // same hash selects the shard on lookup and on insert.
        let key = (self.cache.is_some() || self.flights.is_some())
            .then(|| query_uses_cache(query))
            .filter(|uses_cache| *uses_cache)
            .and_then(|_| {
                KeyBuf::new(
                    group_index,
                    question.qtype,
                    question.qclass,
                    query.header.recursion_desired,
                    query_dnssec_ok(query),
                    &question.name,
                )
            });
        let stored = match (&self.cache, &key) {
            (Some(store), Some(key)) => Some((store, key, store.hash(key.as_bytes()))),
            _ => None,
        };

        let now = self.clock.now();
        let found = stored
            .as_ref()
            .and_then(|(store, key, hash)| store.get(*hash, key.as_bytes(), now));
        let (mut stale, mut previous_backoff) = match self.classify(found, now) {
            Found::Fresh(cached) => {
                let mut answer = cache_hit_response(query, &cached, now);
                align_edns(query, &mut answer);
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                self.emit(ObserveEvent::CacheHit {
                    correlation_id,
                    group: group.clone(),
                });
                self.emit(ObserveEvent::Completed {
                    correlation_id,
                    rcode: answer.header.rcode,
                });
                if let (Some(prefetch), Some((_, key, hash))) = (&self.prefetch, &stored) {
                    self.maybe_prefetch(
                        prefetch, background, query, &group, key, *hash, &cached, now,
                    );
                }
                return Ok(answer);
            }
            Found::Failure(cached) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                self.emit(ObserveEvent::CacheHit {
                    correlation_id,
                    group: group.clone(),
                });
                return self.serve_failure(query, &cached, correlation_id, &group, now);
            }
            Found::StaleNow(cached) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                self.emit(ObserveEvent::CacheHit {
                    correlation_id,
                    group: group.clone(),
                });
                return self.serve_stale(query, &cached, correlation_id, &group);
            }
            Found::Refresh { stale, backoff } => (stale, backoff),
        };
        self.counters.misses.fetch_add(1, Ordering::Relaxed);
        self.emit(ObserveEvent::CacheMiss {
            correlation_id,
            group: group.clone(),
        });

        // Concurrent misses for one key share one upstream query. Only the
        // leader proceeds; a follower returns the leader's outcome, and a
        // follower whose leader was cancelled goes round again.
        let mut announced = false;
        let mut guard = match (&self.flights, &key) {
            (Some(flights), Some(key)) => {
                let flight_hash = flights.hash(key.as_bytes());
                loop {
                    match flights.join_or_lead(flight_hash, key.as_bytes()) {
                        Join::Lead(guard) => break Some(guard),
                        Join::Follow(follower) => {
                            if !announced {
                                announced = true;
                                self.counters.coalesced.fetch_add(1, Ordering::Relaxed);
                                self.emit_cache(CacheEvent::Coalesced {
                                    correlation_id,
                                    group: group.clone(),
                                });
                            }
                            match self.wait_for_flight(follower, stale.as_ref()).await {
                                FlightWait::Done(outcome) => {
                                    return self.finish_follower(
                                        query,
                                        outcome,
                                        correlation_id,
                                        &group,
                                    );
                                }
                                FlightWait::TimedOut => {
                                    if let Some(stale) = &stale {
                                        return self.serve_stale(
                                            query,
                                            stale,
                                            correlation_id,
                                            &group,
                                        );
                                    }
                                }
                                FlightWait::Abandoned => {}
                            }
                        }
                    }
                }
            }
            _ => None,
        };

        // The leader re-checks the cache: another leader may have stored an
        // answer (or recorded a failure) and unregistered between this
        // query's miss and its registration.
        if guard.is_some()
            && let Some((store, key, hash)) = &stored
        {
            let now = self.clock.now();
            match self.classify(store.get(*hash, key.as_bytes(), now), now) {
                Found::Fresh(cached) => {
                    if let Some(guard) = guard {
                        guard.finish(|| Outcome::Cached(Arc::clone(&cached)));
                    }
                    let mut answer = cache_hit_response(query, &cached, now);
                    align_edns(query, &mut answer);
                    self.emit(ObserveEvent::Completed {
                        correlation_id,
                        rcode: answer.header.rcode,
                    });
                    return Ok(answer);
                }
                Found::Failure(cached) => {
                    if let Some(guard) = guard {
                        guard.finish(|| outcome_of_failure(&cached));
                    }
                    return self.serve_failure(query, &cached, correlation_id, &group, now);
                }
                Found::StaleNow(cached) => {
                    if let Some(guard) = guard {
                        guard.finish(|| Outcome::Stale(Arc::clone(&cached)));
                    }
                    return self.serve_stale(query, &cached, correlation_id, &group);
                }
                Found::Refresh {
                    stale: found_stale,
                    backoff,
                } => {
                    stale = found_stale;
                    previous_backoff = backoff;
                }
            }
        }

        // With a client timeout, a stale entry's refresh runs as a background
        // task and this query waits for it only that long.
        if let (Some(stale_entry), Some(timeout), Some((_, key, hash))) = (
            &stale,
            self.serve_stale
                .as_ref()
                .and_then(ServeStale::client_timeout_value),
            &stored,
        ) && let Some(flight) = guard.take()
        {
            match self.spawn_stale_refresh(
                background,
                flight,
                query,
                &group,
                key,
                *hash,
                stale_entry,
            ) {
                Ok(follower) => {
                    return match tokio::time::timeout(timeout, follower.wait()).await {
                        Ok(Wait::Done(outcome)) => {
                            self.finish_follower(query, outcome, correlation_id, &group)
                        }
                        Ok(Wait::Abandoned) | Err(_) => {
                            self.serve_stale(query, stale_entry, correlation_id, &group)
                        }
                    };
                }
                // No runtime or too many refreshes running: wait inline.
                Err(flight) => guard = Some(flight),
            }
        }

        // The lifetime is measured from before the upstream call. A leader
        // that took over from a cancelled one measures from its own start.
        let now = if announced { self.clock.now() } else { now };
        let epoch = self.cache_epoch.load(Ordering::Acquire);
        let result = self
            .query_upstream(
                query,
                &group,
                backends,
                Some(correlation_id),
                stored,
                now,
                epoch,
            )
            .await;
        let stale_used = self.settle_failure(
            query,
            &result,
            stale.as_ref(),
            stored,
            previous_backoff,
            epoch,
        );
        if let Some(guard) = guard {
            guard.finish(|| match &stale_used {
                Some(entry) => Outcome::Stale(Arc::clone(entry)),
                None => outcome_of(&result),
            });
        }
        if let Some(entry) = stale_used {
            return self.serve_stale(query, &entry, correlation_id, &group);
        }
        match result {
            Ok((mut answer, _, _)) => {
                align_edns(query, &mut answer);
                self.emit(ObserveEvent::Completed {
                    correlation_id,
                    rcode: answer.header.rcode,
                });
                Ok(answer)
            }
            Err(error) => {
                self.emit(ObserveEvent::Failed {
                    correlation_id,
                    failure: observe_failure(&error),
                });
                Err(error)
            }
        }
    }

    /// The body of [`Resolver::clear_cache`].
    fn clear_cache(&self) -> usize {
        // Bump first, then lock: an insert that already passed its epoch
        // check holds a shard lock, so the flush below waits for it and
        // removes the entry; any later insert sees the new epoch.
        self.cache_epoch.fetch_add(1, Ordering::AcqRel);
        self.cache.as_ref().map_or(0, Store::clear)
    }

    /// The body of [`Resolver::purge`].
    fn purge(&self, name: &Name, rtype: Option<RecordType>) -> usize {
        self.cache_epoch.fetch_add(1, Ordering::AcqRel);
        self.cache
            .as_ref()
            .map_or(0, |store| store.purge(name, rtype))
    }

    /// The body of [`Resolver::purge_subtree`].
    fn purge_subtree(&self, zone: &Name) -> usize {
        self.cache_epoch.fetch_add(1, Ordering::AcqRel);
        self.cache
            .as_ref()
            .map_or(0, |store| store.purge_subtree(zone))
    }

    /// The body of [`Resolver::cache_stats`].
    fn cache_stats(&self) -> CacheStats {
        let store = self.cache.as_ref().map(Store::stats).unwrap_or_default();
        CacheStats {
            entries: store.entries,
            bytes: store.bytes,
            capacity_bytes: store.capacity_bytes,
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            coalesced: self.counters.coalesced.load(Ordering::Relaxed),
            inserts: store.inserts,
            evictions: store.evictions,
            expirations: store.expirations,
            oversized_rejected: store.oversized_rejected,
            refreshes: self.counters.refreshes.load(Ordering::Relaxed),
            stale_hits: self.counters.stale_hits.load(Ordering::Relaxed),
            failure_hits: self.counters.failure_hits.load(Ordering::Relaxed),
        }
    }

    /// Answers a coalesced follower from its leader's `outcome`, emitting the
    /// follower's terminal event.
    fn finish_follower(
        &self,
        query: &Message,
        outcome: Outcome,
        correlation_id: u64,
        group: &UpstreamGroupId,
    ) -> Result<Message> {
        let mut answer = match outcome {
            Outcome::Stale(entry) => {
                return self.serve_stale(query, &entry, correlation_id, group);
            }
            Outcome::Cached(cached) => cache_hit_response(query, &cached, self.clock.now()),
            Outcome::Raw(answer) => {
                // Not cacheable, so not rewritten: only the transaction
                // fields are the follower's own.
                let mut response = (*answer).clone();
                response.set_edns(None);
                response.header.id = query.header.id;
                response.header.recursion_desired = query.header.recursion_desired;
                response.header.authoritative = false;
                response.questions = query.questions.clone();
                response
            }
            Outcome::Failed(error) => {
                self.emit(ObserveEvent::Failed {
                    correlation_id,
                    failure: observe_failure(&error),
                });
                return Err(error);
            }
        };
        align_edns(query, &mut answer);
        self.emit(ObserveEvent::Completed {
            correlation_id,
            rcode: answer.header.rcode,
        });
        Ok(answer)
    }

    /// Decides what a stored entry means for a query at `now`.
    fn classify(&self, entry: Option<Arc<CachedAnswer>>, now: Instant) -> Found {
        let Some(entry) = entry else {
            return Found::Refresh {
                stale: None,
                backoff: None,
            };
        };
        if let Some(failure) = &entry.failure {
            // An expired failure is kept only to remember its backoff.
            return if now < entry.expires {
                Found::Failure(entry)
            } else {
                Found::Refresh {
                    stale: None,
                    backoff: Some(failure.backoff),
                }
            };
        }
        if now < entry.expires {
            return Found::Fresh(entry);
        }
        if self.serve_stale.is_some() && now < entry.stale_until {
            return if entry.recheck_pending(now) {
                Found::StaleNow(entry)
            } else {
                Found::Refresh {
                    stale: Some(entry),
                    backoff: None,
                }
            };
        }
        Found::Refresh {
            stale: None,
            backoff: None,
        }
    }

    /// Answers from a remembered upstream failure; the caller has counted
    /// the lookup as a hit.
    fn serve_failure(
        &self,
        query: &Message,
        cached: &CachedAnswer,
        correlation_id: u64,
        group: &UpstreamGroupId,
        now: Instant,
    ) -> Result<Message> {
        self.counters.failure_hits.fetch_add(1, Ordering::Relaxed);
        self.emit_cache(CacheEvent::FailureServed {
            correlation_id,
            group: group.clone(),
        });
        if let Some(error) = cached.failure.as_ref().and_then(|f| f.error.clone()) {
            self.emit(ObserveEvent::Failed {
                correlation_id,
                failure: observe_failure(&error),
            });
            return Err(error);
        }
        let mut answer = cache_hit_response(query, cached, now);
        align_edns(query, &mut answer);
        self.emit(ObserveEvent::Completed {
            correlation_id,
            rcode: answer.header.rcode,
        });
        Ok(answer)
    }

    /// Answers from an expired entry (RFC 8767): every record TTL is the
    /// configured reply TTL and an EDNS client also gets Extended DNS Error 3.
    fn serve_stale(
        &self,
        query: &Message,
        entry: &CachedAnswer,
        correlation_id: u64,
        group: &UpstreamGroupId,
    ) -> Result<Message> {
        let reply_ttl = self
            .serve_stale
            .as_ref()
            .map_or(DEFAULT_STALE_REPLY_TTL, ServeStale::reply_ttl_value);
        let mut answer = stale_response(query, entry, reply_ttl);
        align_edns(query, &mut answer);
        mark_stale_answer(query, &mut answer);
        self.counters.stale_hits.fetch_add(1, Ordering::Relaxed);
        self.emit_cache(CacheEvent::StaleServed {
            correlation_id,
            group: group.clone(),
        });
        self.emit(ObserveEvent::Completed {
            correlation_id,
            rcode: answer.header.rcode,
        });
        Ok(answer)
    }

    /// Waits for the flight's leader. A query that holds a stale answer gives
    /// up after the serve-stale client timeout, when one is configured and a
    /// Tokio runtime is available to time it.
    async fn wait_for_flight(
        &self,
        follower: Follower,
        stale: Option<&Arc<CachedAnswer>>,
    ) -> FlightWait {
        let timeout = stale
            .and(self.serve_stale.as_ref())
            .and_then(ServeStale::client_timeout_value)
            .filter(|_| Handle::try_current().is_ok());
        let waited = match timeout {
            Some(timeout) => match tokio::time::timeout(timeout, follower.wait()).await {
                Ok(waited) => waited,
                Err(_) => return FlightWait::TimedOut,
            },
            None => follower.wait().await,
        };
        match waited {
            Wait::Done(outcome) => FlightWait::Done(outcome),
            Wait::Abandoned => FlightWait::Abandoned,
        }
    }

    /// Hands the refresh of an expired entry to a background task that leads
    /// `guard`'s flight, and returns a follower of that flight for the caller
    /// to wait on. Gives the guard back when there is no Tokio runtime or
    /// [`MAX_REFRESH_TASKS`] refreshes already run.
    #[allow(clippy::too_many_arguments)]
    fn spawn_stale_refresh(
        self: &Arc<Self>,
        background: &Mutex<JoinSet<()>>,
        guard: LeaderGuard,
        query: &Message,
        group: &UpstreamGroupId,
        key: &KeyBuf,
        hash: u64,
        stale: &Arc<CachedAnswer>,
    ) -> std::result::Result<Follower, LeaderGuard> {
        let Ok(handle) = Handle::try_current() else {
            return Err(guard);
        };
        let mut tasks = lock(background);
        while tasks.try_join_next().is_some() {}
        if tasks.len() >= MAX_REFRESH_TASKS {
            return Err(guard);
        }
        let follower = guard.follower();
        let task = Arc::clone(self).refresh(
            query.clone(),
            group.clone(),
            key.clone(),
            hash,
            Some(guard),
            Some(Arc::clone(stale)),
        );
        tasks.spawn_on(task, &handle);
        Ok(follower)
    }

    /// Reacts to the outcome of an upstream resolution that may be a failure
    /// (an error, or a `SERVFAIL`/`REFUSED` answer).
    ///
    /// - A failure while `stale` holds an expired answer starts that entry's
    ///   recheck window and returns it: the caller answers stale.
    /// - Otherwise, with failure caching on, the failure is stored with a
    ///   backoff that doubles `previous` (the backoff of the failure that
    ///   expired just before), unless a purge has bumped `epoch`.
    /// - A success forgets an expired remembered failure.
    fn settle_failure(
        &self,
        query: &Message,
        result: &Result<UpstreamAnswer>,
        stale: Option<&Arc<CachedAnswer>>,
        stored: Option<(&Store, &KeyBuf, u64)>,
        previous: Option<Duration>,
        epoch: u64,
    ) -> Option<Arc<CachedAnswer>> {
        if !is_failure(result) {
            if previous.is_some()
                && let Some((store, key, hash)) = stored
            {
                store.forget_failure(hash, key.as_bytes());
            }
            return None;
        }
        // The upstream call may have taken a while: both windows start now.
        let at = self.clock.now();
        if let (Some(entry), Some(policy)) = (stale, &self.serve_stale) {
            entry.defer_recheck(at + policy.failure_recheck_value());
            return Some(Arc::clone(entry));
        }
        if let (Some(policy), Some((store, key, hash))) = (&self.failure_cache, stored) {
            let backoff = previous.map_or(policy.first_backoff(), |previous| {
                policy.next_backoff(previous)
            });
            let (message, error) = match result {
                Ok((answer, _, _)) => {
                    let mut message = answer.clone();
                    message.set_edns(None);
                    (message, None)
                }
                // Never served: an error is replayed as the error itself.
                Err(error) => (local_response(query, Rcode::ServFail), Some(error.clone())),
            };
            let entry = Arc::new(CachedAnswer::failure(
                message,
                error,
                at,
                backoff,
                policy.longest_backoff(),
            ));
            store.insert_if(hash, key.as_bytes(), entry, at, || {
                self.cache_epoch.load(Ordering::Acquire) == epoch
            });
        }
        None
    }

    /// Tries the group's backends in registration order and returns the first
    /// answer together with its normalised cache entry when it is cacheable.
    ///
    /// A cacheable answer is stored here, before the caller publishes it to
    /// any coalesced follower, unless a purge has bumped `epoch` since the
    /// upstream call began. Emits the per-backend upstream events under
    /// `correlation_id` (none for a background refresh, which passes `None`);
    /// the terminal event is the caller's.
    ///
    /// Returns the answer, its normalised entry when it is cacheable, and
    /// whether that entry was actually stored.
    #[allow(clippy::too_many_arguments)]
    async fn query_upstream(
        &self,
        query: &Message,
        group: &UpstreamGroupId,
        backends: &[Box<dyn UpstreamBackend>],
        correlation_id: Option<u64>,
        stored: Option<(&Store, &KeyBuf, u64)>,
        now: Instant,
        epoch: u64,
    ) -> Result<UpstreamAnswer> {
        let observe = |event: &dyn Fn(u64) -> ObserveEvent| {
            if let Some(correlation_id) = correlation_id {
                self.emit(event(correlation_id));
            }
        };
        let mut last_err = None;
        for (backend_index, backend) in backends.iter().enumerate() {
            observe(&|correlation_id| ObserveEvent::UpstreamAttempt {
                correlation_id,
                group: group.clone(),
                backend_index,
            });
            match backend.resolve(query).await {
                Ok(answer) => {
                    observe(&|correlation_id| ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::Success,
                    });
                    let mut was_stored = false;
                    let entry = stored.and_then(|(store, key, hash)| {
                        let entry = Arc::new(cacheable_answer(&answer, now, &self.ttl_policy)?);
                        // An entry too large for its shard is simply not
                        // stored; the answer is still returned.
                        was_stored =
                            store.insert_if(hash, key.as_bytes(), Arc::clone(&entry), now, || {
                                self.cache_epoch.load(Ordering::Acquire) == epoch
                            });
                        Some(entry)
                    });
                    return Ok((answer, entry, was_stored));
                }
                Err(e) if is_retryable(&e) => {
                    observe(&|correlation_id| ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::RetryableFailure,
                    });
                    last_err = Some(e);
                }
                Err(e) => {
                    observe(&|correlation_id| ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::Failure,
                    });
                    return Err(e);
                }
            }
        }
        Err(last_err.expect("at least one backend was tried since backends is non-empty"))
    }

    /// Starts a background refresh of `cached` when prefetch is due; see
    /// [`Prefetch`] for the conditions. Never fails and never blocks: when any
    /// condition is not met, or no Tokio runtime is available, nothing
    /// happens. No sink callback runs here, so holding the task-set lock is
    /// safe.
    #[allow(clippy::too_many_arguments)]
    fn maybe_prefetch(
        self: &Arc<Self>,
        prefetch: &Prefetch,
        background: &Mutex<JoinSet<()>>,
        query: &Message,
        group: &UpstreamGroupId,
        key: &KeyBuf,
        hash: u64,
        cached: &Arc<CachedAnswer>,
        now: Instant,
    ) {
        let hits = cached
            .hits
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if hits < prefetch.min_hits_value() {
            return;
        }
        let lifetime = cached.expires.saturating_duration_since(cached.inserted);
        let remaining = cached.expires.saturating_duration_since(now);
        if remaining.as_nanos() * 100
            > lifetime.as_nanos() * u128::from(prefetch.threshold_percent_value())
        {
            return;
        }
        // Without a runtime there is nowhere to run the refresh.
        let Ok(handle) = Handle::try_current() else {
            return;
        };
        let mut tasks = lock(background);
        while tasks.try_join_next().is_some() {}
        if tasks.len() >= MAX_REFRESH_TASKS {
            return;
        }
        if cached.refreshing.swap(true, Ordering::AcqRel) {
            return;
        }
        // A refresh is a coalescing leader: if another query is already
        // fetching this key, there is nothing to add.
        let guard = match &self.flights {
            Some(flights) => {
                match flights.join_or_lead(flights.hash(key.as_bytes()), key.as_bytes()) {
                    Join::Lead(guard) => Some(guard),
                    Join::Follow(_) => return,
                }
            }
            None => None,
        };
        let task =
            Arc::clone(self).refresh(query.clone(), group.clone(), key.clone(), hash, guard, None);
        tasks.spawn_on(task, &handle);
    }

    /// Fetches a fresh answer in the background and stores it, as a
    /// coalescing leader. Emits only cache events.
    ///
    /// `stale` is the expired entry being revalidated, if that is why the
    /// refresh runs (a prefetch refreshes a fresh entry and has none): when the
    /// refresh fails, that entry's recheck window starts and the flight is
    /// told to answer stale.
    async fn refresh(
        self: Arc<Self>,
        query: Message,
        group: UpstreamGroupId,
        key: KeyBuf,
        hash: u64,
        guard: Option<LeaderGuard>,
        stale: Option<Arc<CachedAnswer>>,
    ) {
        let correlation_id = self.next_correlation_id.fetch_add(1, Ordering::Relaxed);
        self.counters.refreshes.fetch_add(1, Ordering::Relaxed);
        self.emit_cache(CacheEvent::RefreshStarted {
            correlation_id,
            group: group.clone(),
        });
        let refreshed = match (&self.cache, self.backends.get(&group)) {
            (Some(store), Some(backends)) => {
                let now = self.clock.now();
                let epoch = self.cache_epoch.load(Ordering::Acquire);
                let result = self
                    .query_upstream(
                        &query,
                        &group,
                        backends,
                        None,
                        Some((store, &key, hash)),
                        now,
                        epoch,
                    )
                    .await;
                let stale_used = stale.as_ref().and_then(|stale| {
                    self.settle_failure(
                        &query,
                        &result,
                        Some(stale),
                        Some((store, &key, hash)),
                        None,
                        epoch,
                    )
                });
                if let Some(guard) = guard {
                    guard.finish(|| match &stale_used {
                        Some(entry) => Outcome::Stale(Arc::clone(entry)),
                        None => outcome_of(&result),
                    });
                }
                matches!(result, Ok((_, _, true)))
            }
            _ => false,
        };
        self.emit_cache(CacheEvent::RefreshCompleted {
            correlation_id,
            group,
            refreshed,
        });
    }

    fn emit(&self, event: ObserveEvent) {
        if let Some(sink) = &self.observability_sink {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.record(&event)));
        }
    }

    fn emit_cache(&self, event: CacheEvent) {
        if let Some(sink) = &self.observability_sink {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink.record_cache(&event);
            }));
        }
    }

    /// Selects and validates the effective upstream group for one ordinary
    /// query, returning it with its cache-key index. This deliberately
    /// happens before the cache lookup because a hook may choose different
    /// groups for equal DNS questions.
    ///
    /// No resolver mutex is held while invoking the hook. Dropping the
    /// enclosing [`Resolver::resolve`] future drops this in-flight hook call;
    /// hook implementations own cancellation cleanup and must not re-enter
    /// this resolver.
    async fn select_backends(
        &self,
        question: &dns_lattice_model::Question,
        correlation_id: u64,
    ) -> Result<(UpstreamGroupId, u32, &Vec<Box<dyn UpstreamBackend>>)> {
        let static_group = self.policy.resolve_group(&question.name);
        self.emit(ObserveEvent::StaticRoute {
            correlation_id,
            group: static_group.cloned(),
        });
        let group = match &self.route_hook {
            Some(hook) => match hook.select(RouteRequest::new(question, static_group)).await {
                Ok(RouteDecision::Use(group)) => {
                    self.emit(ObserveEvent::HookDecision {
                        correlation_id,
                        decision: HookObserveDecision::Use(group.clone()),
                    });
                    Some(group)
                }
                Ok(RouteDecision::Abstain) => {
                    self.emit(ObserveEvent::HookDecision {
                        correlation_id,
                        decision: HookObserveDecision::Abstain,
                    });
                    static_group.cloned()
                }
                Err(error) => {
                    self.emit(ObserveEvent::HookDecision {
                        correlation_id,
                        decision: HookObserveDecision::Failed,
                    });
                    return Err(Error::Hook(error.to_string()));
                }
            },
            None => static_group.cloned(),
        }
        .ok_or(Error::NoRoute)?;

        let backends = self.backends.get(&group).ok_or(Error::NoRoute)?;
        if backends.is_empty() {
            return Err(Error::NoRoute);
        }
        let index = *self.group_index.get(&group).ok_or(Error::NoRoute)?;
        Ok((group, index, backends))
    }
}

/// EDNS option codes that do not change the answer's content and so leave a
/// query cacheable: NSID (3), COOKIE (10), TCP keepalive (11) and Padding (12).
const CACHEABLE_EDNS_OPTIONS: [u16; 4] = [3, 10, 11, 12];

/// Whether `query` may be answered from, stored in, and coalesced through the
/// cache: exactly one question, opcode `QUERY`, and no EDNS option that can
/// make the answer client-specific (Client Subnet, or any option other than
/// [`CACHEABLE_EDNS_OPTIONS`]). A malformed OPT record is not inspected.
fn query_uses_cache(query: &Message) -> bool {
    query.questions.len() == 1
        && query.header.opcode == Opcode::Query
        && match query.edns() {
            Ok(Some(edns)) => edns
                .options()
                .iter()
                .all(|option| CACHEABLE_EDNS_OPTIONS.contains(&option.code())),
            Ok(None) | Err(_) => true,
        }
}

/// The query's EDNS DO bit for the cache identity: false when the query has
/// no OPT record or a malformed one.
fn query_dnssec_ok(query: &Message) -> bool {
    matches!(query.edns(), Ok(Some(edns)) if edns.dnssec_ok())
}

/// Aligns `answer`'s EDNS(0) OPT record with `query`'s, so an answer never
/// carries another transaction's OPT and an EDNS client always gets one:
///
/// - `query` has no OPT: every OPT is removed from `answer`;
/// - `query` has a valid OPT and `answer` has none or a malformed one: a
///   fresh OPT is attached advertising [`DEFAULT_EDNS_UDP_PAYLOAD_SIZE`],
///   with version 0, the query's DO bit and no options;
/// - both have a valid OPT (a fresh upstream answer): `answer` is kept;
/// - `query`'s OPT is malformed: `answer` is left untouched.
fn align_edns(query: &Message, answer: &mut Message) {
    match query.edns() {
        Ok(None) => answer.set_edns(None),
        Ok(Some(query_edns)) => {
            if !matches!(answer.edns(), Ok(Some(_))) {
                let mut edns = Edns::new(DEFAULT_EDNS_UDP_PAYLOAD_SIZE);
                edns.set_dnssec_ok(query_edns.dnssec_ok());
                answer.set_edns(Some(edns));
            }
        }
        Err(_) => {}
    }
}

/// Whether `record` is an EDNS(0) OPT pseudo-record, whose `TTL` field is
/// not a lifetime.
fn is_opt(record: &ResourceRecord) -> bool {
    record.rtype == RecordType::Other(OPT_RTYPE)
}

/// Every record of every section except OPT pseudo-records, mutably.
fn ttl_records_mut(message: &mut Message) -> impl Iterator<Item = &mut ResourceRecord> {
    message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
        .filter(|record| !is_opt(record))
}

/// Projects a cached entry onto a response for `query` at `now`.
///
/// Cache entries represent reusable answer content, not a prior client's DNS
/// transaction. The response echoes the current query's message id,
/// question section and RD bit, clears AA (a cached answer is not
/// authoritative data), and reduces every non-OPT record TTL by the whole
/// seconds elapsed since the entry was stored, keeping it at least 1. The
/// QR, RA and RCODE header fields and the order of every record in every
/// section are kept exactly as stored.
fn cache_hit_response(query: &Message, cached: &CachedAnswer, now: Instant) -> Message {
    let elapsed = now.saturating_duration_since(cached.inserted).as_secs();
    let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
    let mut response = cached.message.clone();
    response.header.id = query.header.id;
    response.header.recursion_desired = query.header.recursion_desired;
    response.header.authoritative = false;
    response.questions = query.questions.clone();
    for record in ttl_records_mut(&mut response) {
        record.ttl = record.ttl.saturating_sub(elapsed).max(1);
    }
    response
}

/// Returns a locally synthesized Fake IP response when `query` is handled by
/// `fake_ip`, or `None` when the ordinary resolver pipeline must handle it.
///
/// Only IN A, IN AAAA, and canonical IN reverse PTR questions can be handled. A
/// synthesized response intentionally bypasses the resolver cache and every
/// upstream backend: its lifetime is the pool mapping lifetime and the pool
/// is the authority for its reverse range.
fn fake_ip_answer(query: &Message, fake_ip: &FakeIpResolverConfig) -> Result<Option<Message>> {
    let Some(question) = query.questions.first() else {
        return Ok(None);
    };
    if question.qclass != Class::In {
        return Ok(None);
    }

    match question.qtype {
        RecordType::A if fake_ip.policy.matches(&question.name) => {
            if !fake_ip.pool.ipv4_enabled() {
                return Ok(Some(local_response(query, Rcode::NoError)));
            }
            fake_ip_ttl(fake_ip.pool.ttl())?;
            let mut answer = local_response(query, Rcode::NoError);
            match fake_ip.pool.allocate_ipv4_with_ttl(question.name.clone()) {
                Ok((address, lifetime)) => answer.answers.push(ResourceRecord {
                    name: question.name.clone(),
                    rtype: RecordType::A,
                    class: Class::In,
                    ttl: fake_ip_ttl(lifetime)?,
                    rdata: RData::A(address),
                }),
                Err(Error::FakeIpFamilyDisabled) => {}
                Err(error) => return Err(error),
            }
            Ok(Some(answer))
        }
        RecordType::Aaaa if fake_ip.policy.matches(&question.name) => {
            if !fake_ip.pool.ipv6_enabled() {
                return Ok(Some(local_response(query, Rcode::NoError)));
            }
            fake_ip_ttl(fake_ip.pool.ttl())?;
            let mut answer = local_response(query, Rcode::NoError);
            match fake_ip.pool.allocate_ipv6_with_ttl(question.name.clone()) {
                Ok((address, lifetime)) => answer.answers.push(ResourceRecord {
                    name: question.name.clone(),
                    rtype: RecordType::Aaaa,
                    class: Class::In,
                    ttl: fake_ip_ttl(lifetime)?,
                    rdata: RData::Aaaa(address),
                }),
                Err(Error::FakeIpFamilyDisabled) => {}
                Err(error) => return Err(error),
            }
            Ok(Some(answer))
        }
        RecordType::Ptr => fake_ip_ptr_answer(query, fake_ip),
        _ => Ok(None),
    }
}

fn fake_ip_ptr_answer(query: &Message, fake_ip: &FakeIpResolverConfig) -> Result<Option<Message>> {
    let question = query.questions.first().expect("checked by caller");
    let address = match parse_reverse_name(&question.name) {
        Some(address) => address,
        None => return Ok(None),
    };
    let mapping = match address {
        std::net::IpAddr::V4(address) if fake_ip.pool.contains_ipv4(address) => {
            fake_ip.pool.lookup_ipv4_with_ttl(address)
        }
        std::net::IpAddr::V6(address) if fake_ip.pool.contains_ipv6(address) => {
            fake_ip.pool.lookup_ipv6_with_ttl(address)
        }
        _ => return Ok(None),
    };
    let mut answer = local_response(
        query,
        if mapping.is_some() {
            Rcode::NoError
        } else {
            Rcode::NxDomain
        },
    );
    if let Some((name, lifetime)) = mapping {
        answer.answers.push(ResourceRecord {
            name: question.name.clone(),
            rtype: RecordType::Ptr,
            class: Class::In,
            ttl: fake_ip_ttl(lifetime)?,
            rdata: RData::Ptr(name),
        });
    }
    Ok(Some(answer))
}

fn local_response(query: &Message, rcode: Rcode) -> Message {
    let mut header = query.header;
    header.qr = true;
    header.rcode = rcode;
    Message {
        header,
        questions: query.questions.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn fake_ip_ttl(lifetime: Duration) -> Result<u32> {
    u32::try_from(lifetime.as_secs()).map_err(|_| Error::FakeIpTtlOutOfRange)
}

/// Parses a canonical `in-addr.arpa` or `ip6.arpa` owner name.
///
/// Non-canonical reverse names are intentionally routed normally, so only a
/// pool range for which this resolver is authoritative receives local DNS
/// semantics.
fn parse_reverse_name(name: &Name) -> Option<std::net::IpAddr> {
    let labels: Vec<_> = name.labels().collect();
    if labels.len() == 6
        && labels[4].eq_ignore_ascii_case(b"in-addr")
        && labels[5].eq_ignore_ascii_case(b"arpa")
    {
        let mut octets = [0_u8; 4];
        for (index, label) in labels[..4].iter().enumerate() {
            let text = std::str::from_utf8(label).ok()?;
            let value = text.parse::<u8>().ok()?;
            if value.to_string() != text {
                return None;
            }
            octets[3 - index] = value;
        }
        return Some(std::net::IpAddr::V4(Ipv4Addr::from(octets)));
    }
    if labels.len() == 34
        && labels[32].eq_ignore_ascii_case(b"ip6")
        && labels[33].eq_ignore_ascii_case(b"arpa")
    {
        let mut bytes = [0_u8; 16];
        for (index, label) in labels[..32].iter().enumerate() {
            if label.len() != 1 {
                return None;
            }
            let nibble = match label[0] {
                b'0'..=b'9' => label[0] - b'0',
                b'a'..=b'f' => label[0] - b'a' + 10,
                b'A'..=b'F' => label[0] - b'A' + 10,
                _ => return None,
            };
            let target = 31 - index;
            if target % 2 == 0 {
                bytes[target / 2] |= nibble << 4;
            } else {
                bytes[target / 2] |= nibble;
            }
        }
        return Some(std::net::IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

/// What one upstream resolution produced: the answer, its normalised cache
/// entry when it is cacheable, and whether that entry was stored.
type UpstreamAnswer = (Message, Option<Arc<CachedAnswer>>, bool);

/// The TTL of a stale answer when no policy says otherwise (RFC 8767 §4).
const DEFAULT_STALE_REPLY_TTL: u32 = 30;

/// What a lookup found.
enum Found {
    /// A fresh answer.
    Fresh(Arc<CachedAnswer>),
    /// A remembered upstream failure that is still being served.
    Failure(Arc<CachedAnswer>),
    /// An expired answer inside the recheck window of a failed refresh: serve
    /// it without asking the upstream.
    StaleNow(Arc<CachedAnswer>),
    /// Nothing usable: ask the upstream. `stale` is an expired answer kept for
    /// serve-stale, `backoff` the length of a failure that just expired.
    Refresh {
        stale: Option<Arc<CachedAnswer>>,
        backoff: Option<Duration>,
    },
}

/// How waiting on another query's flight ended.
enum FlightWait {
    Done(Outcome),
    Abandoned,
    /// The serve-stale client timeout passed.
    TimedOut,
}

/// Whether `result` is an upstream failure: an error, or a `SERVFAIL` or
/// `REFUSED` answer.
fn is_failure(result: &Result<UpstreamAnswer>) -> bool {
    match result {
        Ok((answer, _, _)) => matches!(answer.header.rcode, Rcode::ServFail | Rcode::Refused),
        Err(_) => true,
    }
}

/// The outcome a coalescing leader publishes for a remembered failure.
fn outcome_of_failure(entry: &CachedAnswer) -> Outcome {
    match entry.failure.as_ref().and_then(|f| f.error.clone()) {
        Some(error) => Outcome::Failed(error),
        None => Outcome::Raw(Arc::new(entry.message.clone())),
    }
}

/// Projects an expired entry onto a stale response for `query`: like a cache
/// hit, but every non-OPT record TTL is `reply_ttl`.
fn stale_response(query: &Message, entry: &CachedAnswer, reply_ttl: u32) -> Message {
    let mut response = entry.message.clone();
    response.header.id = query.header.id;
    response.header.recursion_desired = query.header.recursion_desired;
    response.header.authoritative = false;
    response.questions = query.questions.clone();
    for record in ttl_records_mut(&mut response) {
        record.ttl = reply_ttl;
    }
    response
}

/// The Extended DNS Error option code (RFC 8914).
const EDE_OPTION_CODE: u16 = 15;

/// The Extended DNS Error info code "Stale Answer" (RFC 8914).
const EDE_STALE_ANSWER: u16 = 3;

/// Adds Extended DNS Error 3 ("Stale Answer") to `answer`'s OPT record when
/// `query` carries a well-formed one; other queries get no OPT.
fn mark_stale_answer(query: &Message, answer: &mut Message) {
    if !matches!(query.edns(), Ok(Some(_))) {
        return;
    }
    if let Ok(Some(mut edns)) = answer.edns()
        && let Ok(option) =
            EdnsOption::new(EDE_OPTION_CODE, EDE_STALE_ANSWER.to_be_bytes().to_vec())
    {
        edns.push_option(option);
        answer.set_edns(Some(edns));
    }
}

/// The outcome a coalescing leader publishes for `result`.
fn outcome_of(result: &Result<UpstreamAnswer>) -> Outcome {
    match result {
        Ok((_, Some(entry), _)) => Outcome::Cached(Arc::clone(entry)),
        Ok((answer, None, _)) => Outcome::Raw(Arc::new(answer.clone())),
        Err(error) => Outcome::Failed(error.clone()),
    }
}

/// Returns whether `err` should cause the failover loop to try the next
/// backend in the group rather than propagate immediately: all three
/// backend-level failure variants —
/// [`Error::Timeout`], [`Error::Transport`], and [`Error::Tls`] — are
/// retryable, since none indicate a client-input problem and a different
/// backend in the same group may have independent connectivity/TLS
/// configuration.
fn is_retryable(err: &Error) -> bool {
    matches!(err, Error::Timeout | Error::Transport(_) | Error::Tls(_))
}

fn observe_failure(error: &Error) -> ObserveFailure {
    match error {
        Error::NoRoute => ObserveFailure::NoRoute,
        Error::Hook(_) => ObserveFailure::Hook,
        Error::Timeout => ObserveFailure::Timeout,
        Error::Transport(_) => ObserveFailure::Transport,
        Error::Tls(_) => ObserveFailure::Tls,
        _ => ObserveFailure::Other,
    }
}

/// Gates and normalises an upstream `answer` for storage, or returns `None`
/// if it must not be cached.
///
/// Only a clean answer is stored: opcode `QUERY`, `TC` clear, an EDNS
/// extended RCODE of 0 (an answer whose OPT record does not parse is not
/// stored), and either positive (`NoError` with at least one answer record)
/// or negative (`NxDomain`, or `NoError` with an empty answer section).
///
/// The stored copy has its OPT record removed. Every remaining record TTL is
/// clamped into `policy`'s positive or negative bounds. The entry TTL is the
/// minimum non-OPT record TTL over all sections. For a negative answer it is
/// further limited to the negative TTL: min(SOA TTL, SOA `MINIMUM`) (RFC 2308
/// §5) clamped into the negative bounds, written back to the first authority
/// SOA's TTL so it counts down on hits (RFC 2308 §6); with no SOA in the
/// authority section it is `policy.negative_without_soa` (clamped likewise),
/// and a policy of `None` stores no such answer. An entry TTL of 0 is not
/// stored. `inserted` anchors the countdown and expiry.
fn cacheable_answer(
    answer: &Message,
    inserted: Instant,
    policy: &TtlPolicy,
) -> Option<CachedAnswer> {
    if answer.header.opcode != Opcode::Query || answer.header.truncated {
        return None;
    }
    match answer.edns() {
        Ok(None) => {}
        Ok(Some(edns)) if edns.extended_rcode() == 0 => {}
        Ok(Some(_)) | Err(_) => return None,
    }
    let negative = match answer.header.rcode {
        Rcode::NoError => answer.answers.is_empty(),
        Rcode::NxDomain => true,
        _ => return None,
    };
    let bounds = if negative {
        policy.negative
    } else {
        policy.positive
    };

    let mut message = answer.clone();
    // OPT is per-transaction (payload size, DO, options such as COOKIE) and
    // must never be cached (RFC 6891 §6.1.1); a hit gets a fresh one.
    message.set_edns(None);
    for record in ttl_records_mut(&mut message) {
        record.ttl = bounds.clamp(record.ttl);
    }
    let negative_ttl = if negative {
        let soa = message.authorities.iter_mut().find_map(|record| {
            if let RData::Soa { minimum, .. } = record.rdata {
                Some((record, minimum))
            } else {
                None
            }
        });
        Some(match soa {
            Some((record, minimum)) => {
                record.ttl = bounds.clamp(record.ttl.min(minimum));
                record.ttl
            }
            None => bounds.clamp(policy.negative_without_soa?),
        })
    } else {
        None
    };
    let records_ttl = ttl_records_mut(&mut message).map(|record| record.ttl).min();
    let ttl = match (negative_ttl, records_ttl) {
        (Some(negative), Some(records)) => negative.min(records),
        (Some(ttl), None) | (None, Some(ttl)) => ttl,
        (None, None) => return None,
    };
    if ttl == 0 {
        return None;
    }
    Some(
        CachedAnswer::new(
            message,
            inserted,
            inserted + Duration::from_secs(u64::from(ttl)),
        )
        .retained_for(policy.stale_window),
    )
}

/// Builds a [`Resolver`] from a split-DNS policy and one or more upstream
/// backends per group.
pub struct ResolverBuilder {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Vec<Box<dyn UpstreamBackend>>>,
    clock: Box<dyn Clock + Send + Sync>,
    cache: CacheConfig,
    fake_ip: Option<FakeIpResolverConfig>,
    route_hook: Option<Box<dyn RouteHook>>,
    observability_sink: Option<Arc<dyn ObservabilitySink>>,
}

impl ResolverBuilder {
    /// Registers an upstream backend used to answer queries routed to
    /// `group`, appended after any backend already registered for that
    /// group. [`Resolver::resolve`] tries a group's backends in this
    /// registration order, falling over to the next one on a retryable
    /// error.
    ///
    /// `backend` is any [`crate::upstream::UpstreamBackend`] implementation
    /// — e.g. [`crate::upstream::UdpBackend`]/
    /// [`crate::upstream::TcpBackend`] for real transport, or a
    /// test-only fake implementing the trait directly.
    pub fn backend(
        mut self,
        group: UpstreamGroupId,
        backend: impl UpstreamBackend + 'static,
    ) -> Self {
        self.backends
            .entry(group)
            .or_default()
            .push(Box::new(backend));
        self
    }

    /// Enables local Fake IP synthesis for names selected by `policy`.
    ///
    /// Matching IN A/AAAA questions allocate or reuse an address in `pool`
    /// and return a local response without consulting the cache or an
    /// upstream. If the selected address family is disabled in `pool`, the
    /// resolver instead returns a local NOERROR empty answer (NODATA), still
    /// without a cache or upstream lookup. Canonical IN PTR questions inside
    /// one of the pool's ranges are likewise handled locally: live mappings
    /// return PTR, and an unmapped address returns NXDOMAIN. All other
    /// questions follow normal split-DNS resolution.
    pub fn fake_ip(mut self, pool: Arc<FakeIpPool>, policy: FakeIpPolicy) -> Self {
        self.fake_ip = Some(FakeIpResolverConfig { pool, policy });
        self
    }

    /// Configures one optional dynamic upstream-group selection hook.
    ///
    /// For each non-local query, the hook receives the first question and
    /// the static split-DNS candidate. [`crate::hooks::RouteDecision::Use`]
    /// replaces that candidate, while `Abstain` retains it. The resulting
    /// group must be registered and nonempty; otherwise resolution returns
    /// [`Error::NoRoute`] without static fallback, cache access, or an
    /// upstream call. Fake IP local answers remain terminal and never invoke
    /// the hook.
    ///
    /// The hook owns timeout, retry, and cancellation cleanup. A dropped
    /// [`Resolver::resolve`] call drops the in-flight hook future. Hooks must
    /// not call `resolve` on this same resolver directly or indirectly.
    pub fn route_hook(mut self, hook: impl RouteHook + 'static) -> Self {
        self.route_hook = Some(Box::new(hook));
        self
    }

    /// Adds an optional, non-authoritative synchronous event sink.
    ///
    /// The resolver invokes it outside internal locks. Panics are isolated and
    /// never affect DNS answers, route selection, cache behavior, or retries.
    pub fn observability_sink(mut self, sink: Arc<dyn ObservabilitySink>) -> Self {
        self.observability_sink = Some(sink);
        self
    }

    /// Configures the answer cache: its memory bound, shard count, TTL
    /// clamps, and the opt-in prefetch, serve-stale and failure-caching
    /// policies. Without this call the resolver uses [`CacheConfig::new`], a
    /// store bounded to 16 MiB (estimated). Pass [`CacheConfig::disabled`] to
    /// keep nothing; every query then goes to its upstream group.
    ///
    /// The configuration is read once, by [`ResolverBuilder::build`]; a later
    /// call replaces an earlier one.
    pub fn cache(mut self, config: CacheConfig) -> Self {
        self.cache = config;
        self
    }

    /// Substitutes the clock used to compute and check cache expiry.
    /// Crate-private: no public API for clock injection.
    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Clock + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> Resolver {
        let mut groups: Vec<&UpstreamGroupId> = self.backends.keys().collect();
        groups.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let group_index = groups
            .into_iter()
            .zip(0_u32..)
            .map(|(group, index)| (group.clone(), index))
            .collect();
        let cache = self
            .cache
            .store_enabled()
            .then(|| Store::new(self.cache.max_bytes_value(), self.cache.shards_value()));
        Resolver {
            inner: Arc::new(ResolverInner {
                policy: self.policy,
                backends: self.backends,
                group_index,
                clock: self.clock,
                cache,
                ttl_policy: self.cache.ttl_policy(),
                flights: self
                    .cache
                    .coalesce_enabled()
                    .then(|| Arc::new(Flights::new())),
                cache_epoch: AtomicU64::new(0),
                prefetch: self.cache.prefetch_policy().cloned(),
                serve_stale: self.cache.serve_stale_policy().cloned(),
                failure_cache: self
                    .cache
                    .store_enabled()
                    .then(|| self.cache.failure_cache_policy().cloned())
                    .flatten(),
                counters: QueryCounters::default(),
                fake_ip: self.fake_ip,
                route_hook: self.route_hook,
                observability_sink: self.observability_sink,
                next_correlation_id: AtomicU64::new(1),
            }),
            background: Mutex::new(JoinSet::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dns_lattice_model::{
        Class, DomainPattern, Header, Name, Opcode, Question, Rcode, RecordType,
    };

    /// A minimal test-only fake [`UpstreamBackend`] that always returns a
    /// fixed answer, proving routing wiring without modelling any real
    /// upstream transport behavior.
    struct FixedBackend(Message);

    #[async_trait]
    impl UpstreamBackend for FixedBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            Ok(self.0.clone())
        }
    }

    fn fixed_backend(answer: Message) -> FixedBackend {
        FixedBackend(answer)
    }

    /// A test-only fake [`UpstreamBackend`] that always fails with a fixed
    /// error, proving error propagation without modelling any real
    /// upstream transport behavior.
    struct FailingBackend(Error);

    #[async_trait]
    impl UpstreamBackend for FailingBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            Err(self.0.clone())
        }
    }

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn query_for(name: &str) -> Message {
        Message {
            header: Header {
                id: 1,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: n(name),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn answer_tagged(id: u16) -> Message {
        let mut msg = query_for("tag.example");
        msg.header.id = id;
        msg.header.qr = true;
        msg
    }

    #[tokio::test]
    async fn routes_exact_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::exact(n("host.corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(42)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .await
            .expect("routed to corp backend");
        assert_eq!(answer.header.id, 42);
    }

    #[tokio::test]
    async fn routes_suffix_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(7)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .await
            .expect("routed to corp backend via suffix");
        assert_eq!(answer.header.id, 7);
    }

    #[tokio::test]
    async fn routes_wildcard_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::wildcard(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(9)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .await
            .expect("routed to corp backend via wildcard");
        assert_eq!(answer.header.id, 9);
    }

    #[tokio::test]
    async fn routes_unmatched_query_to_default_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .default_group(UpstreamGroupId::new("public"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("public"),
                fixed_backend(answer_tagged(3)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("routed to default group");
        assert_eq!(answer.header.id, 3);
    }

    #[tokio::test]
    async fn no_route_when_no_match_and_no_default_group() {
        let policy = SplitDnsPolicy::builder().build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect_err("no rule and no default group configured");
        assert_eq!(err, Error::NoRoute);
    }

    #[tokio::test]
    async fn no_route_when_matched_group_has_no_registered_backend() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .await
            .expect_err("matched group has no backend registered");
        assert_eq!(err, Error::NoRoute);
    }

    #[tokio::test]
    async fn failover_first_backend_succeeds_second_never_called() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let calls = Arc::new(AtomicUsize::new(0));
        let second = CountingBackend {
            answer: answer_tagged(2),
            calls: calls.clone(),
        };
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("g"), fixed_backend(answer_tagged(1)))
            .backend(UpstreamGroupId::new("g"), second)
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("first backend answers");
        assert_eq!(answer.header.id, 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "second backend never called once the first succeeds"
        );
    }

    #[tokio::test]
    async fn failover_first_backend_fails_second_succeeds() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("g"), FailingBackend(Error::Timeout))
            .backend(UpstreamGroupId::new("g"), fixed_backend(answer_tagged(99)))
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("second backend answers after first times out");
        assert_eq!(
            answer.header.id, 99,
            "routed answer is the second backend's"
        );
    }

    #[tokio::test]
    async fn failover_tls_error_retries_to_next_backend() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("g"),
                FailingBackend(Error::Tls("certificate expired".to_string())),
            )
            .backend(UpstreamGroupId::new("g"), fixed_backend(answer_tagged(5)))
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("tls error on first backend retries to the second");
        assert_eq!(answer.header.id, 5);
    }

    #[tokio::test]
    async fn failover_all_backends_fail_returns_last_error() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("g"), FailingBackend(Error::Timeout))
            .backend(
                UpstreamGroupId::new("g"),
                FailingBackend(Error::Transport("connection refused".to_string())),
            )
            .build();

        let err = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect_err("both backends fail");
        assert_eq!(
            err,
            Error::Transport("connection refused".to_string()),
            "the last attempted backend's error is returned, not the first's"
        );
    }

    #[tokio::test]
    async fn single_backend_group_still_behaves_as_before() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("g"), fixed_backend(answer_tagged(11)))
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("single-backend group still resolves");
        assert_eq!(answer.header.id, 11);
    }

    #[tokio::test]
    async fn backend_error_propagates_as_is() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                FailingBackend(Error::NameTooLong),
            )
            .build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .await
            .expect_err("backend failure propagates");
        assert_eq!(err, Error::NameTooLong);
    }

    // --- Dedicated fake upstream backend + cache test suite (deferred from
    // the routing and cache slice -----------------------------------------

    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use dns_lattice_model::{RData, ResourceRecord};
    use tokio::sync::Notify;

    use crate::hooks::{RouteDecision, RouteHook, RouteHookError, RouteRequest};
    use crate::observability::{ObservabilitySink, ObserveEvent};

    #[derive(Clone)]
    struct PoolClock(Arc<Mutex<Instant>>);

    impl PoolClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, duration: Duration) {
            *self.0.lock().expect("pool clock mutex poisoned") += duration;
        }
    }

    impl crate::fakeip::Clock for PoolClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("pool clock mutex poisoned")
        }
    }

    /// A configurable fake in-process [`UpstreamBackend`] that returns a
    /// fixed answer and counts how many times it was called, so cache-hit
    /// tests can assert the backend is *not* called again on a hit.
    struct CountingBackend {
        answer: Message,
        calls: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<ObserveEvent>>);

    impl ObservabilitySink for RecordingSink {
        fn record(&self, event: &ObserveEvent) {
            self.0
                .lock()
                .expect("event mutex poisoned")
                .push(event.clone());
        }
    }

    struct PanickingSink;

    impl ObservabilitySink for PanickingSink {
        fn record(&self, _: &ObserveEvent) {
            panic!("observer failure must be isolated");
        }
    }

    #[async_trait]
    impl UpstreamBackend for CountingBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answer.clone())
        }
    }

    struct FixedHook {
        decision: std::result::Result<RouteDecision, RouteHookError>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl RouteHook for FixedHook {
        async fn select(
            &self,
            _request: RouteRequest<'_>,
        ) -> std::result::Result<RouteDecision, RouteHookError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.decision.clone()
        }
    }

    struct SequencedHook {
        decisions: Mutex<Vec<RouteDecision>>,
    }

    #[async_trait]
    impl RouteHook for SequencedHook {
        async fn select(
            &self,
            _request: RouteRequest<'_>,
        ) -> std::result::Result<RouteDecision, RouteHookError> {
            Ok(self
                .decisions
                .lock()
                .expect("hook decisions mutex poisoned")
                .remove(0))
        }
    }

    struct RecordingHook {
        decision: RouteDecision,
        static_groups: Arc<Mutex<Vec<Option<UpstreamGroupId>>>>,
    }

    #[async_trait]
    impl RouteHook for RecordingHook {
        async fn select(
            &self,
            request: RouteRequest<'_>,
        ) -> std::result::Result<RouteDecision, RouteHookError> {
            self.static_groups
                .lock()
                .expect("recorded static groups mutex poisoned")
                .push(request.static_group().cloned());
            Ok(self.decision.clone())
        }
    }

    struct PendingHook {
        entered: Arc<Notify>,
        dropped: Arc<AtomicBool>,
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl RouteHook for PendingHook {
        async fn select(
            &self,
            _request: RouteRequest<'_>,
        ) -> std::result::Result<RouteDecision, RouteHookError> {
            let _drop_signal = DropSignal(self.dropped.clone());
            self.entered.notify_waiters();
            std::future::pending().await
        }
    }

    fn a_answer(name: &str, ttl: u32) -> Message {
        let mut msg = query_for(name);
        msg.header.qr = true;
        msg.answers.push(ResourceRecord {
            name: n(name),
            rtype: RecordType::A,
            class: Class::In,
            ttl,
            rdata: RData::A(Ipv4Addr::new(203, 0, 113, 1)),
        });
        msg
    }

    fn nxdomain_answer(name: &str, soa_minimum: Option<u32>) -> Message {
        let mut msg = query_for(name);
        msg.header.qr = true;
        msg.header.rcode = Rcode::NxDomain;
        if let Some(minimum) = soa_minimum {
            msg.authorities.push(ResourceRecord {
                name: n("example.com"),
                rtype: RecordType::Soa,
                class: Class::In,
                ttl: 3600,
                rdata: RData::Soa {
                    mname: n("ns1.example.com"),
                    rname: n("hostmaster.example.com"),
                    serial: 1,
                    refresh: 3600,
                    retry: 600,
                    expire: 604_800,
                    minimum,
                },
            });
        }
        msg
    }

    fn nodata_answer(name: &str) -> Message {
        // NoError, empty answer section: NODATA per RFC 2308.
        query_for_response(name)
    }

    fn query_for_response(name: &str) -> Message {
        let mut msg = query_for(name);
        msg.header.qr = true;
        msg
    }

    fn resolver_with_counting_backend(
        policy: SplitDnsPolicy,
        group: &str,
        answer: Message,
        clock: FakeClock,
    ) -> (Resolver, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = CountingBackend {
            answer,
            calls: calls.clone(),
        };
        let resolver = Resolver::builder(policy)
            .clock(clock)
            .backend(UpstreamGroupId::new(group), backend)
            .build();
        (resolver, calls)
    }

    #[tokio::test]
    async fn cache_hit_does_not_call_backend_again() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            a_answer("example.com", 300),
            FakeClock::new(),
        );

        let first = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("first resolve populates cache");
        let second = resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("second resolve served from cache");

        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "backend called only once");
    }

    #[tokio::test]
    async fn observability_reports_ordered_cache_miss_and_hit_without_affecting_resolution() {
        let sink = Arc::new(RecordingSink::default());
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (base, calls) = resolver_with_counting_backend(
            policy,
            "g",
            a_answer("example.com", 300),
            FakeClock::new(),
        );
        let base = Arc::try_unwrap(base.inner)
            .ok()
            .expect("the resolver is not shared");
        let resolver = ResolverBuilder {
            policy: base.policy,
            backends: base.backends,
            clock: base.clock,
            cache: CacheConfig::new(),
            fake_ip: base.fake_ip,
            route_hook: base.route_hook,
            observability_sink: Some(sink.clone()),
        }
        .build();

        resolver.resolve(&query_for("example.com")).await.unwrap();
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let events = sink.0.lock().unwrap().clone();
        assert!(matches!(
            events[0],
            ObserveEvent::QueryReceived {
                correlation_id: 1,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            ObserveEvent::StaticRoute {
                correlation_id: 1,
                ..
            }
        ));
        assert!(matches!(
            events[2],
            ObserveEvent::CacheMiss {
                correlation_id: 1,
                ..
            }
        ));
        assert!(matches!(
            events[3],
            ObserveEvent::UpstreamAttempt {
                correlation_id: 1,
                backend_index: 0,
                ..
            }
        ));
        assert!(matches!(
            events[4],
            ObserveEvent::UpstreamOutcome {
                correlation_id: 1,
                outcome: UpstreamObserveOutcome::Success,
                ..
            }
        ));
        assert!(matches!(
            events[5],
            ObserveEvent::Completed {
                correlation_id: 1,
                ..
            }
        ));
        assert!(matches!(
            events[6],
            ObserveEvent::QueryReceived {
                correlation_id: 2,
                ..
            }
        ));
        assert!(matches!(
            events[7],
            ObserveEvent::StaticRoute {
                correlation_id: 2,
                ..
            }
        ));
        assert!(matches!(
            events[8],
            ObserveEvent::CacheHit {
                correlation_id: 2,
                ..
            }
        ));
        assert!(matches!(
            events[9],
            ObserveEvent::Completed {
                correlation_id: 2,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn panicking_observability_sink_is_non_authoritative() {
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            fixed_backend(a_answer("example.com", 300)),
        )
        .observability_sink(Arc::new(PanickingSink))
        .build();

        assert!(resolver.resolve(&query_for("example.com")).await.is_ok());
    }

    #[tokio::test]
    async fn observability_starts_empty_queries_before_no_route_failure() {
        let sink = Arc::new(RecordingSink::default());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .observability_sink(sink.clone())
            .build();
        let mut query = query_for("example.com");
        query.questions.clear();

        assert_eq!(resolver.resolve(&query).await, Err(Error::NoRoute));
        assert!(matches!(
            sink.0.lock().unwrap().as_slice(),
            [
                ObserveEvent::QueryReceived {
                    name: None,
                    rtype: None,
                    class: None,
                    ..
                },
                ObserveEvent::Failed {
                    failure: ObserveFailure::NoRoute,
                    ..
                },
            ]
        ));
    }

    #[tokio::test]
    async fn observability_marks_fake_ip_terminal_before_cache_or_upstream() {
        let sink = Arc::new(RecordingSink::default());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(
                fake_ip_pool(PoolClock::new()),
                fake_ip_policy("example.com"),
            )
            .observability_sink(sink.clone())
            .build();

        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert!(matches!(
            sink.0.lock().unwrap().as_slice(),
            [
                ObserveEvent::QueryReceived { .. },
                ObserveEvent::FakeIpTerminal { .. },
                ObserveEvent::Completed { .. },
            ]
        ));
    }

    #[tokio::test]
    async fn observability_records_hook_and_timeout_failures_in_order() {
        let sink = Arc::new(RecordingSink::default());
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .route_hook(FixedHook {
            decision: Err(RouteHookError::new("denied")),
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .observability_sink(sink.clone())
        .build();
        assert!(matches!(
            resolver.resolve(&query_for("example.com")).await,
            Err(Error::Hook(_))
        ));
        assert!(matches!(
            sink.0.lock().unwrap().as_slice(),
            [
                ObserveEvent::QueryReceived { .. },
                ObserveEvent::StaticRoute { .. },
                ObserveEvent::HookDecision {
                    decision: HookObserveDecision::Failed,
                    ..
                },
                ObserveEvent::Failed {
                    failure: ObserveFailure::Hook,
                    ..
                },
            ]
        ));

        sink.0.lock().unwrap().clear();
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(UpstreamGroupId::new("g"), FailingBackend(Error::Timeout))
        .observability_sink(sink.clone())
        .build();
        assert_eq!(
            resolver.resolve(&query_for("example.com")).await,
            Err(Error::Timeout)
        );
        assert!(matches!(
            sink.0.lock().unwrap().as_slice(),
            [
                ObserveEvent::QueryReceived { .. },
                ObserveEvent::StaticRoute { .. },
                ObserveEvent::CacheMiss { .. },
                ObserveEvent::UpstreamAttempt { .. },
                ObserveEvent::UpstreamOutcome {
                    outcome: UpstreamObserveOutcome::RetryableFailure,
                    ..
                },
                ObserveEvent::Failed {
                    failure: ObserveFailure::Timeout,
                    ..
                },
            ]
        ));
    }

    #[tokio::test]
    async fn cache_hit_preserves_the_current_query_identity_and_questions() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            a_answer("example.com", 300),
            FakeClock::new(),
        );
        let first = query_for_type("example.com", RecordType::A, Class::In, 91);
        // Names match case-insensitively, but the response must echo the
        // current query's own spelling.
        let second = query_for_type("ExAmPlE.CoM", RecordType::A, Class::In, 92);

        resolver
            .resolve(&first)
            .await
            .expect("first resolve populates cache");
        let cached = resolver
            .resolve(&second)
            .await
            .expect("second resolve is served from cache");

        assert_eq!(cached.header.id, 92);
        assert_eq!(cached.questions, second.questions);
        assert_eq!(cached.questions[0].name.to_string(), "ExAmPlE.CoM.");
        assert_eq!(
            cached.answers[0].rdata,
            RData::A(Ipv4Addr::new(203, 0, 113, 1))
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "second query is a cache hit"
        );
    }

    #[tokio::test]
    async fn cache_identity_separates_generated_question_type_and_class_pairs() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            a_answer("example.com", 300),
            FakeClock::new(),
        );

        let cases = [
            (RecordType::A, Class::In, 1),
            (RecordType::Aaaa, Class::In, 2),
            (RecordType::A, Class::Ch, 3),
            (RecordType::Other(65280), Class::Other(65280), 4),
        ];

        for (rtype, class, id) in cases {
            resolver
                .resolve(&query_for_type("example.com", rtype, class, id))
                .await
                .expect("each distinct cache identity resolves");
        }
        assert_eq!(calls.load(Ordering::SeqCst), cases.len());

        for (rtype, class, id) in cases {
            let cached = resolver
                .resolve(&query_for_type("example.com", rtype, class, id + 10))
                .await
                .expect("same type/class pair is cached");
            assert_eq!(cached.header.id, id + 10);
            assert_eq!(cached.questions[0].qtype, rtype);
            assert_eq!(cached.questions[0].qclass, class);
        }
        assert_eq!(calls.load(Ordering::SeqCst), cases.len());
    }

    #[tokio::test]
    async fn cache_entry_still_hit_just_before_ttl_elapses() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let clock = FakeClock::new();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            a_answer("example.com", 300),
            clock.clone(),
        );

        resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("first resolve populates cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(299));

        resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("still cached before ttl elapses");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cache hit before expiry");
    }

    #[tokio::test]
    async fn negative_answer_is_cached_with_soa_minimum_ttl() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            nxdomain_answer("missing.example.com", Some(300)),
            FakeClock::new(),
        );

        let first = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .expect("nxdomain is Ok(Message), not Err");
        assert_eq!(first.header.rcode, Rcode::NxDomain);
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .expect("served from negative cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "negative answer cached");
    }

    #[tokio::test]
    async fn negative_answer_without_soa_uses_fixed_floor_ttl() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            nxdomain_answer("missing.example.com", None),
            FakeClock::new(),
        );

        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .expect("nxdomain without soa still Ok");
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .expect("served from cache using the fixed floor ttl");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "negative answer cached via floor"
        );
    }

    #[tokio::test]
    async fn nodata_answer_is_cached_as_negative() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let (resolver, calls) = resolver_with_counting_backend(
            policy,
            "g",
            nodata_answer("empty.example.com"),
            FakeClock::new(),
        );

        resolver
            .resolve(&query_for("empty.example.com"))
            .await
            .expect("nodata is Ok(Message)");
        resolver
            .resolve(&query_for("empty.example.com"))
            .await
            .expect("served from cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "nodata answer cached");
    }

    #[tokio::test]
    async fn expired_cache_entry_triggers_a_fresh_backend_call() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let clock = FakeClock::new();
        let (resolver, calls) =
            resolver_with_counting_backend(policy, "g", a_answer("example.com", 10), clock.clone());

        resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("first resolve populates cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(11));

        resolver
            .resolve(&query_for("example.com"))
            .await
            .expect("expired entry re-queries the backend");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "ttl-expired entry is not served from cache"
        );
    }

    #[tokio::test]
    async fn hook_use_overrides_the_static_group() {
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let static_calls = Arc::new(AtomicUsize::new(0));
        let selected_calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("static"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("static"),
            CountingBackend {
                answer: answer_tagged(1),
                calls: static_calls.clone(),
            },
        )
        .backend(
            UpstreamGroupId::new("selected"),
            CountingBackend {
                answer: answer_tagged(2),
                calls: selected_calls.clone(),
            },
        )
        .route_hook(FixedHook {
            decision: Ok(RouteDecision::Use(UpstreamGroupId::new("selected"))),
            calls: hook_calls.clone(),
        })
        .build();

        let answer = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(answer.header.id, 2);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(static_calls.load(Ordering::SeqCst), 0);
        assert_eq!(selected_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hook_abstain_uses_the_static_group() {
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("static"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("static"),
            CountingBackend {
                answer: answer_tagged(3),
                calls: backend_calls.clone(),
            },
        )
        .route_hook(FixedHook {
            decision: Ok(RouteDecision::Abstain),
            calls: Arc::new(AtomicUsize::new(0)),
        })
        .build();

        assert_eq!(
            resolver
                .resolve(&query_for("example.com"))
                .await
                .unwrap()
                .header
                .id,
            3
        );
        assert_eq!(backend_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hook_observes_static_candidate_and_can_supply_a_route_without_one() {
        let static_groups = Arc::new(Mutex::new(Vec::new()));
        let static_resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("static"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("static"),
            fixed_backend(answer_tagged(30)),
        )
        .route_hook(RecordingHook {
            decision: RouteDecision::Abstain,
            static_groups: static_groups.clone(),
        })
        .build();
        assert_eq!(
            static_resolver
                .resolve(&query_for("static.example"))
                .await
                .unwrap()
                .header
                .id,
            30
        );

        let dynamic_resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .backend(
                UpstreamGroupId::new("dynamic"),
                fixed_backend(answer_tagged(31)),
            )
            .route_hook(RecordingHook {
                decision: RouteDecision::Use(UpstreamGroupId::new("dynamic")),
                static_groups: static_groups.clone(),
            })
            .build();
        assert_eq!(
            dynamic_resolver
                .resolve(&query_for("dynamic.example"))
                .await
                .unwrap()
                .header
                .id,
            31
        );
        assert_eq!(
            *static_groups.lock().unwrap(),
            vec![Some(UpstreamGroupId::new("static")), None]
        );
    }

    #[tokio::test]
    async fn hook_abstain_without_static_route_returns_no_route() {
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .backend(
                UpstreamGroupId::new("unused"),
                CountingBackend {
                    answer: answer_tagged(4),
                    calls: backend_calls.clone(),
                },
            )
            .route_hook(FixedHook {
                decision: Ok(RouteDecision::Abstain),
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .build();

        assert_eq!(
            resolver.resolve(&query_for("example.com")).await,
            Err(Error::NoRoute)
        );
        assert_eq!(backend_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hook_selected_unknown_or_empty_group_returns_no_route_without_fallback() {
        for group in ["unknown", "empty"] {
            let static_calls = Arc::new(AtomicUsize::new(0));
            let builder = Resolver::builder(
                SplitDnsPolicy::builder()
                    .default_group(UpstreamGroupId::new("static"))
                    .build(),
            )
            .backend(
                UpstreamGroupId::new("static"),
                CountingBackend {
                    answer: answer_tagged(5),
                    calls: static_calls.clone(),
                },
            );
            let mut resolver = builder
                .route_hook(FixedHook {
                    decision: Ok(RouteDecision::Use(UpstreamGroupId::new(group))),
                    calls: Arc::new(AtomicUsize::new(0)),
                })
                .build();
            if group == "empty" {
                Arc::get_mut(&mut resolver.inner)
                    .expect("the resolver is not shared")
                    .backends
                    .insert(UpstreamGroupId::new("empty"), Vec::new());
            }

            assert_eq!(
                resolver.resolve(&query_for("example.com")).await,
                Err(Error::NoRoute)
            );
            assert_eq!(
                static_calls.load(Ordering::SeqCst),
                0,
                "static backend must not receive a hook-selected {group} route"
            );
        }
    }

    #[tokio::test]
    async fn hook_error_is_not_cached_retried_or_fallen_back() {
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("static"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("static"),
            CountingBackend {
                answer: answer_tagged(6),
                calls: backend_calls.clone(),
            },
        )
        .route_hook(FixedHook {
            decision: Err(RouteHookError::new("policy unavailable")),
            calls: hook_calls.clone(),
        })
        .build();

        for _ in 0..2 {
            assert_eq!(
                resolver.resolve(&query_for("example.com")).await,
                Err(Error::Hook("policy unavailable".to_string()))
            );
        }
        assert_eq!(hook_calls.load(Ordering::SeqCst), 2);
        assert_eq!(backend_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cache_len(&resolver), 0);
    }

    #[tokio::test]
    async fn cache_is_scoped_to_the_effective_hook_selected_group() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        // A fixed clock keeps the cached TTLs equal to the first answer's:
        // with the real clock a slow run would see them counted down.
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .clock(FakeClock::new())
            .backend(
                UpstreamGroupId::new("first"),
                CountingBackend {
                    answer: a_answer("example.com", 300),
                    calls: first_calls.clone(),
                },
            )
            .backend(
                UpstreamGroupId::new("second"),
                CountingBackend {
                    answer: answer_tagged(8),
                    calls: second_calls.clone(),
                },
            )
            .route_hook(SequencedHook {
                decisions: Mutex::new(vec![
                    RouteDecision::Use(UpstreamGroupId::new("first")),
                    RouteDecision::Use(UpstreamGroupId::new("second")),
                    RouteDecision::Use(UpstreamGroupId::new("first")),
                ]),
            })
            .build();

        let first = resolver
            .resolve(&query_for_type("example.com", RecordType::A, Class::In, 41))
            .await
            .unwrap();
        let second = resolver
            .resolve(&query_for_type("example.com", RecordType::A, Class::In, 42))
            .await
            .unwrap();
        let cached_first = resolver
            .resolve(&query_for_type("example.com", RecordType::A, Class::In, 43))
            .await
            .unwrap();

        assert_eq!(first.answers[0].ttl, 300);
        assert_eq!(
            second.header.id, 8,
            "second route cannot reuse first route cache"
        );
        assert_eq!(cached_first.header.id, 43);
        assert_eq!(cached_first.questions, query_for("example.com").questions);
        assert_eq!(
            cached_first.answers, first.answers,
            "first route has its own cache hit"
        );
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_resolve_drops_the_hook_future_without_holding_cache_lock() {
        let entered = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let resolver = Arc::new(
            Resolver::builder(SplitDnsPolicy::builder().build())
                .route_hook(PendingHook {
                    entered: entered.clone(),
                    dropped: dropped.clone(),
                })
                .build(),
        );
        let entered_wait = entered.notified();
        let task_resolver = resolver.clone();
        let task =
            tokio::spawn(async move { task_resolver.resolve(&query_for("example.com")).await });

        entered_wait.await;
        assert!(
            resolver
                .inner
                .cache
                .as_ref()
                .is_none_or(Store::all_unlocked),
            "no cache shard lock is held across the hook await"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            dropped.load(Ordering::SeqCst),
            "hook future was dropped on cancellation"
        );
    }

    fn query_for_type(name: &str, qtype: RecordType, qclass: Class, id: u16) -> Message {
        let mut query = query_for(name);
        query.header.id = id;
        query.questions[0].qtype = qtype;
        query.questions[0].qclass = qclass;
        query
    }

    fn fake_ip_policy(name: &str) -> FakeIpPolicy {
        FakeIpPolicy::builder()
            .rule(DomainPattern::suffix(n(name)))
            .build()
    }

    fn fake_ip_pool(clock: PoolClock) -> Arc<FakeIpPool> {
        Arc::new(
            FakeIpPool::builder()
                .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
                .ttl(Duration::from_secs(30))
                .clock(clock)
                .build()
                .unwrap(),
        )
    }

    fn fake_ip_pool_ipv6(clock: PoolClock) -> Arc<FakeIpPool> {
        Arc::new(
            FakeIpPool::builder()
                .ipv6_range(
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::2".parse().unwrap(),
                )
                .ttl(Duration::from_secs(30))
                .clock(clock)
                .build()
                .unwrap(),
        )
    }

    #[tokio::test]
    async fn fake_ip_a_answer_is_local_and_bypasses_upstream_and_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let backend = CountingBackend {
            answer: a_answer("example.test", 300),
            calls: calls.clone(),
        };
        let pool = fake_ip_pool(PoolClock::new());
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(UpstreamGroupId::new("g"), backend)
        .fake_ip(pool, fake_ip_policy("example.test"))
        .route_hook(FixedHook {
            decision: Ok(RouteDecision::Use(UpstreamGroupId::new("g"))),
            calls: hook_calls.clone(),
        })
        .build();

        let first = resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::A,
                Class::In,
                41,
            ))
            .await
            .unwrap();
        let second = resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::A,
                Class::In,
                42,
            ))
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            hook_calls.load(Ordering::SeqCst),
            0,
            "Fake IP is terminal before hooks"
        );
        assert_eq!(first.header.id, 41);
        assert_eq!(second.header.id, 42, "synthetic answers are not cached");
        assert!(first.header.qr);
        assert_eq!(first.questions, query_for("www.example.test").questions);
        assert_eq!(first.answers[0].ttl, 30);
        assert_eq!(first.answers[0].rdata, second.answers[0].rdata);
    }

    #[tokio::test]
    async fn fake_ip_disabled_family_returns_local_nodata() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: a_answer("example.test", 300),
                calls: calls.clone(),
            },
        )
        .fake_ip(
            fake_ip_pool(PoolClock::new()),
            fake_ip_policy("example.test"),
        )
        .build();

        let answer = resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::Aaaa,
                Class::In,
                9,
            ))
            .await
            .unwrap();

        assert_eq!(answer.header.rcode, Rcode::NoError);
        assert!(answer.answers.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fake_ip_ptr_is_local_and_expires_with_its_mapping() {
        let pool_clock = PoolClock::new();
        let pool = fake_ip_pool(pool_clock.clone());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(pool.clone(), fake_ip_policy("example.test"))
            .build();
        let address = pool.allocate_ipv4(n("www.example.test")).unwrap();
        let reverse = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            address.octets()[3],
            address.octets()[2],
            address.octets()[1],
            address.octets()[0]
        );

        let found = resolver
            .resolve(&query_for_type(&reverse, RecordType::Ptr, Class::In, 11))
            .await
            .unwrap();
        assert_eq!(found.header.rcode, Rcode::NoError);
        assert_eq!(found.answers[0].rdata, RData::Ptr(n("www.example.test")));
        assert_eq!(found.answers[0].ttl, 30);

        pool_clock.advance(Duration::from_secs(30));
        let expired = resolver
            .resolve(&query_for_type(&reverse, RecordType::Ptr, Class::In, 12))
            .await
            .unwrap();
        assert_eq!(expired.header.rcode, Rcode::NxDomain);
        assert!(expired.answers.is_empty());
    }

    #[tokio::test]
    async fn fake_ip_answer_ttl_never_outlives_existing_mapping() {
        let pool_clock = PoolClock::new();
        let pool = fake_ip_pool(pool_clock.clone());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(pool.clone(), fake_ip_policy("example.test"))
            .build();
        pool.allocate_ipv4(n("www.example.test")).unwrap();

        pool_clock.advance(Duration::from_secs(29));
        let answer = resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::A,
                Class::In,
                20,
            ))
            .await
            .unwrap();

        assert_eq!(answer.answers[0].ttl, 1);
    }

    #[tokio::test]
    async fn fake_ip_ptr_ttl_never_outlives_existing_mapping() {
        let pool_clock = PoolClock::new();
        let pool = fake_ip_pool(pool_clock.clone());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(pool.clone(), fake_ip_policy("example.test"))
            .build();
        let address = pool.allocate_ipv4(n("www.example.test")).unwrap();
        let reverse = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            address.octets()[3],
            address.octets()[2],
            address.octets()[1],
            address.octets()[0]
        );

        pool_clock.advance(Duration::from_secs(29));
        let answer = resolver
            .resolve(&query_for_type(&reverse, RecordType::Ptr, Class::In, 21))
            .await
            .unwrap();

        assert_eq!(answer.answers[0].ttl, 1);
    }

    #[tokio::test]
    async fn fake_ip_ipv6_ptr_is_local() {
        let pool = fake_ip_pool_ipv6(PoolClock::new());
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(pool.clone(), fake_ip_policy("example.test"))
            .build();
        let address = pool.allocate_ipv6(n("www.example.test")).unwrap();
        let reverse = address
            .octets()
            .iter()
            .rev()
            .flat_map(|byte| [format!("{:x}", byte & 0x0f), format!("{:x}", byte >> 4)])
            .collect::<Vec<_>>()
            .join(".");

        let answer = resolver
            .resolve(&query_for_type(
                &format!("{reverse}.ip6.arpa"),
                RecordType::Ptr,
                Class::In,
                22,
            ))
            .await
            .unwrap();

        assert_eq!(answer.header.rcode, Rcode::NoError);
        assert_eq!(answer.answers[0].rdata, RData::Ptr(n("www.example.test")));
    }

    #[tokio::test]
    async fn normal_queries_and_outside_reverse_ranges_still_use_upstream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(
            FakeIpPool::builder()
                .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
                .ttl(Duration::from_secs(u64::MAX))
                .clock(PoolClock::new())
                .build()
                .unwrap(),
        );
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: answer_tagged(77),
                calls: calls.clone(),
            },
        )
        .fake_ip(pool, fake_ip_policy("selected.test"))
        .build();

        for query in [
            query_for_type("miss.test", RecordType::A, Class::In, 1),
            query_for_type("selected.test", RecordType::A, Class::Ch, 2),
            query_for_type("selected.test", RecordType::Txt, Class::In, 3),
            query_for_type("1.0.0.203.in-addr.arpa", RecordType::Ptr, Class::In, 4),
        ] {
            let answer = resolver.resolve(&query).await.unwrap();
            assert_eq!(answer.header.id, 77);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn unrepresentable_fake_ip_ttl_fails_before_allocation() {
        let pool = Arc::new(
            FakeIpPool::builder()
                .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
                .ttl(Duration::from_secs(u64::from(u32::MAX) + 1))
                .clock(PoolClock::new())
                .build()
                .unwrap(),
        );
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .fake_ip(pool.clone(), fake_ip_policy("example.test"))
            .build();

        assert_eq!(
            resolver
                .resolve(&query_for_type(
                    "www.example.test",
                    RecordType::A,
                    Class::In,
                    23
                ))
                .await,
            Err(Error::FakeIpTtlOutOfRange)
        );
        assert!(pool.snapshot().mappings.is_empty());
    }

    #[tokio::test]
    async fn disabled_fake_ip_families_return_nodata_even_with_unrepresentable_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let pool = Arc::new(
            FakeIpPool::builder()
                .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
                .ttl(Duration::from_secs(u64::from(u32::MAX) + 1))
                .clock(PoolClock::new())
                .build()
                .unwrap(),
        );
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: answer_tagged(78),
                calls: calls.clone(),
            },
        )
        .fake_ip(pool.clone(), fake_ip_policy("example.test"))
        .build();

        let aaaa = resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::Aaaa,
                Class::In,
                24,
            ))
            .await
            .unwrap();
        assert_eq!(aaaa.header.rcode, Rcode::NoError);
        assert!(aaaa.answers.is_empty());
        assert!(pool.snapshot().mappings.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let ipv6_only_pool = Arc::new(
            FakeIpPool::builder()
                .ipv6_range(
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::2".parse().unwrap(),
                )
                .ttl(Duration::from_secs(u64::from(u32::MAX) + 1))
                .clock(PoolClock::new())
                .build()
                .unwrap(),
        );
        let ipv6_only_resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: answer_tagged(79),
                calls: calls.clone(),
            },
        )
        .fake_ip(ipv6_only_pool.clone(), fake_ip_policy("example.test"))
        .build();

        let a = ipv6_only_resolver
            .resolve(&query_for_type(
                "www.example.test",
                RecordType::A,
                Class::In,
                25,
            ))
            .await
            .unwrap();
        assert_eq!(a.header.rcode, Rcode::NoError);
        assert!(a.answers.is_empty());
        assert!(ipv6_only_pool.snapshot().mappings.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    // --- Cache correctness: countdown, negative TTL, clamps, gating, hit
    // projection, and golden record order ------------------------------------

    use dns_lattice_model::Edns;

    /// A fake backend that returns its answers in order, repeating the last
    /// one, and counts its calls.
    struct SequencedBackend {
        answers: Mutex<Vec<Message>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UpstreamBackend for SequencedBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().expect("answers mutex poisoned");
            Ok(if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0].clone()
            })
        }
    }

    fn record(name: &str, rtype: RecordType, ttl: u32, rdata: RData) -> ResourceRecord {
        ResourceRecord {
            name: n(name),
            rtype,
            class: Class::In,
            ttl,
            rdata,
        }
    }

    fn a_record(name: &str, ttl: u32, last_octet: u8) -> ResourceRecord {
        record(
            name,
            RecordType::A,
            ttl,
            RData::A(Ipv4Addr::new(203, 0, 113, last_octet)),
        )
    }

    fn soa_record(ttl: u32, minimum: u32) -> ResourceRecord {
        record(
            "example.com",
            RecordType::Soa,
            ttl,
            RData::Soa {
                mname: n("ns1.example.com"),
                rname: n("hostmaster.example.com"),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 604_800,
                minimum,
            },
        )
    }

    /// A resolver with one default group backed by a counting fake that
    /// always returns `answer`, on a fake clock.
    fn cache_resolver(answer: Message) -> (Resolver, Arc<AtomicUsize>, FakeClock) {
        let clock = FakeClock::new();
        let (resolver, calls) = resolver_with_counting_backend(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
            "g",
            answer,
            clock.clone(),
        );
        (resolver, calls, clock)
    }

    /// The TTLs of every record in every section, in order.
    fn ttls(message: &Message) -> Vec<u32> {
        message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .map(|record| record.ttl)
            .collect()
    }

    #[tokio::test]
    async fn cached_ttls_count_down_by_whole_elapsed_seconds_in_every_section() {
        let mut answer = a_answer("example.com", 300);
        answer.authorities.push(record(
            "example.com",
            RecordType::Ns,
            600,
            RData::Ns(n("ns1.example.com")),
        ));
        answer
            .additionals
            .push(a_record("ns1.example.com", 400, 53));
        let (resolver, calls, clock) = cache_resolver(answer);

        let first = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(ttls(&first), [300, 600, 400]);

        clock.advance(Duration::from_millis(120_900));
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ttls(&hit),
            [180, 480, 280],
            "120.9 s elapsed counts as 120 whole seconds"
        );
    }

    #[tokio::test]
    async fn cache_entry_is_a_miss_exactly_when_its_ttl_elapses() {
        let (resolver, calls, clock) = cache_resolver(a_answer("example.com", 300));
        resolver.resolve(&query_for("example.com")).await.unwrap();

        clock.advance(Duration::from_secs(299));
        let last_hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(last_hit.answers[0].ttl, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(1));
        let refreshed = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "a miss at inserted + ttl");
        assert_eq!(refreshed.answers[0].ttl, 300);
    }

    /// Whether no cache entry keeps an OPT record.
    fn cache_holds_no_opt(resolver: &Resolver) -> bool {
        resolver
            .inner
            .cache
            .as_ref()
            .is_none_or(|store| store.all_entries(|entry| entry.message.edns() == Ok(None)))
    }

    /// The number of entries in the resolver's answer store.
    fn cache_len(resolver: &Resolver) -> usize {
        resolver.inner.cache.as_ref().map_or(0, Store::len)
    }

    #[tokio::test]
    async fn opt_record_is_never_stored_counted_down_or_used_as_a_lifetime() {
        // OPT TTL field 0: counting it would make the entry TTL 0.
        let mut plain = a_answer("example.com", 300);
        plain.set_edns(Some(Edns::new(4096)));
        let (resolver, calls, clock) = cache_resolver(plain);
        let query = edns_query_for("example.com", 4096, false);
        let first = resolver.resolve(&query).await.unwrap();
        assert_eq!(
            first.edns().unwrap(),
            Some(Edns::new(4096)),
            "a fresh answer keeps its own OPT"
        );
        assert!(cache_holds_no_opt(&resolver), "the stored copy has no OPT");
        clock.advance(Duration::from_secs(100));
        let hit = resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "OPT TTL 0 does not block");
        assert_eq!(hit.answers[0].ttl, 200);
        assert_eq!(hit.edns().unwrap(), Some(Edns::new(1232)), "a fresh OPT");

        // OPT TTL field 98 304 (version 1, DO): above the positive clamp and
        // above the answer TTL, so using it as a lifetime would show.
        let mut edns = Edns::new(1232);
        edns.set_version(1).set_dnssec_ok(true);
        let mut flagged = a_answer("example.com", 300);
        flagged.set_edns(Some(edns));
        assert!(flagged.additionals[0].ttl > 86_400);
        let (resolver, calls, clock) = cache_resolver(flagged);
        resolver.resolve(&query_for("example.com")).await.unwrap();
        clock.advance(Duration::from_secs(299));
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(hit.answers[0].ttl, 1);
        assert_eq!(hit.edns().unwrap(), None);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "lifetime is the A TTL");
    }

    #[tokio::test]
    async fn negative_ttl_is_the_minimum_of_soa_ttl_and_soa_minimum() {
        // SOA TTL 3600, MINIMUM 300: 300 wins and the SOA TTL is rewritten.
        let (resolver, calls, clock) =
            cache_resolver(nxdomain_answer("missing.example.com", Some(300)));
        let first = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(first.authorities[0].ttl, 3600, "upstream answer unchanged");
        let hit = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(hit.authorities[0].ttl, 300);
        clock.advance(Duration::from_secs(100));
        let hit = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(hit.authorities[0].ttl, 200, "the SOA counts down");
        clock.advance(Duration::from_secs(200));
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // SOA TTL 120, MINIMUM 900: the SOA TTL wins (this was MINIMUM only).
        let mut answer = query_for_response("missing.example.com");
        answer.header.rcode = Rcode::NxDomain;
        answer.authorities.push(soa_record(120, 900));
        let (resolver, calls, clock) = cache_resolver(answer);
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        clock.advance(Duration::from_secs(119));
        let hit = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(hit.authorities[0].ttl, 1);
        clock.advance(Duration::from_secs(1));
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn negative_answer_without_soa_lives_sixty_seconds() {
        for answer in [
            nxdomain_answer("missing.example.com", None),
            nodata_answer("missing.example.com"),
        ] {
            let (resolver, calls, clock) = cache_resolver(answer);
            resolver
                .resolve(&query_for("missing.example.com"))
                .await
                .unwrap();
            clock.advance(Duration::from_secs(59));
            resolver
                .resolve(&query_for("missing.example.com"))
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            clock.advance(Duration::from_secs(1));
            resolver
                .resolve(&query_for("missing.example.com"))
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn negative_entry_never_outlives_another_record_in_the_answer() {
        // An NXDOMAIN that follows a CNAME: the CNAME's 30 s TTL caps the
        // 300 s negative TTL.
        let mut answer = nxdomain_answer("alias.example.com", Some(300));
        answer.answers.push(record(
            "alias.example.com",
            RecordType::Cname,
            30,
            RData::Cname(n("gone.example.com")),
        ));
        let (resolver, calls, clock) = cache_resolver(answer);
        resolver
            .resolve(&query_for("alias.example.com"))
            .await
            .unwrap();
        clock.advance(Duration::from_secs(29));
        let hit = resolver
            .resolve(&query_for("alias.example.com"))
            .await
            .unwrap();
        assert_eq!(hit.answers[0].ttl, 1);
        assert_eq!(hit.authorities[0].ttl, 271);
        clock.advance(Duration::from_secs(1));
        resolver
            .resolve(&query_for("alias.example.com"))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn record_ttls_are_clamped_to_one_day_and_negative_ones_to_one_hour() {
        let (resolver, calls, clock) = cache_resolver(a_answer("example.com", 1_000_000));
        let first = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(first.answers[0].ttl, 1_000_000, "upstream answer unchanged");
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(hit.answers[0].ttl, 86_400);
        clock.advance(Duration::from_secs(86_399));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let mut answer = query_for_response("missing.example.com");
        answer.header.rcode = Rcode::NxDomain;
        answer.authorities.push(soa_record(172_800, 86_400));
        let (resolver, calls, clock) = cache_resolver(answer);
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        let hit = resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(hit.authorities[0].ttl, 3_600);
        clock.advance(Duration::from_secs(3_600));
        resolver
            .resolve(&query_for("missing.example.com"))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn answers_that_are_not_clean_are_returned_but_never_cached() {
        let with_rcode = |rcode| {
            let mut answer = a_answer("example.com", 300);
            answer.header.rcode = rcode;
            answer
        };
        let mut truncated = a_answer("example.com", 300);
        truncated.header.truncated = true;
        let mut truncated_negative = nxdomain_answer("example.com", Some(300));
        truncated_negative.header.truncated = true;
        let mut extended_rcode = a_answer("example.com", 300);
        let mut edns = Edns::new(1232);
        edns.set_extended_rcode(1);
        extended_rcode.set_edns(Some(edns));
        let mut malformed_opt = a_answer("example.com", 300);
        malformed_opt.additionals.push(ResourceRecord {
            name: n("not-root.example.com"),
            rtype: RecordType::Other(OPT_RTYPE),
            class: Class::Other(1232),
            ttl: 0,
            rdata: RData::Unknown {
                rtype: OPT_RTYPE,
                data: Vec::new(),
            },
        });
        let mut status_opcode = a_answer("example.com", 300);
        status_opcode.header.opcode = Opcode::Status;

        let cases = [
            ("SERVFAIL with records", with_rcode(Rcode::ServFail)),
            ("REFUSED with records", with_rcode(Rcode::Refused)),
            ("FORMERR with records", with_rcode(Rcode::FormErr)),
            ("NOTIMP with records", with_rcode(Rcode::NotImp)),
            ("unassigned rcode", with_rcode(Rcode::Other(11))),
            ("TC=1 positive", truncated),
            ("TC=1 negative", truncated_negative),
            ("TTL 0 positive", a_answer("example.com", 0)),
            (
                "SOA MINIMUM 0 negative",
                nxdomain_answer("example.com", Some(0)),
            ),
            ("extended RCODE 1", extended_rcode),
            ("malformed OPT", malformed_opt),
            ("opcode STATUS", status_opcode),
        ];
        for (label, answer) in cases {
            let (resolver, calls, _clock) = cache_resolver(answer.clone());
            let first = resolver.resolve(&query_for("example.com")).await.unwrap();
            // The query carries no OPT, so the returned answer carries none.
            let mut expected = answer.clone();
            expected.set_edns(None);
            assert_eq!(first, expected, "{label}: the answer is returned as-is");
            resolver.resolve(&query_for("example.com")).await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2, "{label}: not cached");
            assert_eq!(cache_len(&resolver), 0, "{label}");
        }
    }

    #[tokio::test]
    async fn queries_without_exactly_one_question_or_with_another_opcode_bypass_the_cache() {
        let sink = Arc::new(RecordingSink::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .clock(FakeClock::new())
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: a_answer("example.com", 300),
                calls: calls.clone(),
            },
        )
        .observability_sink(sink.clone())
        .build();

        let mut two_questions = query_for("example.com");
        two_questions.questions.push(Question {
            name: n("extra.example.com"),
            qtype: RecordType::Aaaa,
            qclass: Class::In,
        });
        let mut notify = query_for("example.com");
        notify.header.opcode = Opcode::Notify;
        for query in [&two_questions, &two_questions, &notify, &notify] {
            resolver.resolve(query).await.unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(cache_len(&resolver), 0);
        let misses = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| matches!(event, ObserveEvent::CacheMiss { .. }))
            .count();
        assert_eq!(misses, 4, "a bypassed query is reported as a cache miss");

        // An ordinary query is still cached and is not served by the
        // bypassed ones.
        resolver.resolve(&query_for("example.com")).await.unwrap();
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn cache_hit_echoes_the_query_rd_bit_and_clears_aa() {
        let mut answer = a_answer("example.com", 300);
        answer.header.authoritative = true;
        answer.header.recursion_available = true;
        let (resolver, calls, _clock) = cache_resolver(answer);

        let first = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert!(first.header.authoritative, "upstream answer unchanged");
        let hit = resolver
            .resolve(&query_for_type("example.com", RecordType::A, Class::In, 7))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(hit.header.id, 7);
        assert!(!hit.header.authoritative);
        assert!(hit.header.recursion_desired);
        assert!(hit.header.recursion_available);
        assert!(hit.header.qr);
        assert_eq!(hit.header.rcode, Rcode::NoError);

        // RD is part of the cache identity: RD=0 is a separate entry.
        let mut no_rd = query_for_type("example.com", RecordType::A, Class::In, 8);
        no_rd.header.recursion_desired = false;
        resolver.resolve(&no_rd).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let hit = resolver.resolve(&no_rd).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!hit.header.recursion_desired, "RD echoes the query");
        assert!(!hit.header.authoritative);
    }

    #[tokio::test]
    async fn an_expired_entry_is_removed_when_a_lookup_finds_it() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut servfail = query_for_response("example.com");
        servfail.header.rcode = Rcode::ServFail;
        let clock = FakeClock::new();
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .clock(clock.clone())
        .backend(
            UpstreamGroupId::new("g"),
            SequencedBackend {
                answers: Mutex::new(vec![a_answer("example.com", 10), servfail]),
                calls: calls.clone(),
            },
        )
        .build();

        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(cache_len(&resolver), 1);
        clock.advance(Duration::from_secs(10));
        let refreshed = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(refreshed.header.rcode, Rcode::ServFail);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            cache_len(&resolver),
            0,
            "the expired entry is gone and SERVFAIL was not stored"
        );
    }

    /// Clears the parts of `message` a cache hit may legitimately change
    /// (message id and non-OPT record TTLs) so the rest can be compared.
    fn without_id_and_ttls(message: &Message) -> Message {
        let mut message = message.clone();
        message.header.id = 0;
        for record in ttl_records_mut(&mut message) {
            record.ttl = 0;
        }
        message
    }

    /// Resolves `answer`'s question twice, 7 s apart, and checks that the
    /// hit equals the upstream answer field for field and byte for byte
    /// except for the id and the counted-down TTLs. When `answer` carries an
    /// OPT record it must be `Edns::new(1232)` with any DO bit; the query
    /// then carries an OPT with the same DO bit, so the fresh OPT attached
    /// to the hit equals it.
    async fn assert_cache_hit_is_golden(answer: Message) -> Message {
        let mut query = query_for("unused.example");
        query.questions = answer.questions.clone();
        if let Some(answer_edns) = answer.edns().unwrap() {
            let mut edns = Edns::new(4096);
            edns.set_dnssec_ok(answer_edns.dnssec_ok());
            query.set_edns(Some(edns));
        }
        let (resolver, calls, clock) = cache_resolver(answer.clone());
        let first = resolver.resolve(&query).await.unwrap();
        assert_eq!(first, answer);
        clock.advance(Duration::from_secs(7));
        let mut again = query.clone();
        again.header.id = 0xBEEF;
        let hit = resolver.resolve(&again).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "served from the cache");
        assert_eq!(hit.header.id, 0xBEEF);

        assert_eq!(without_id_and_ttls(&hit), without_id_and_ttls(&answer));
        assert_eq!(
            without_id_and_ttls(&hit).encode().unwrap(),
            without_id_and_ttls(&answer).encode().unwrap(),
            "the wire form differs only in id and TTLs"
        );
        let expected: Vec<u32> = answer
            .answers
            .iter()
            .chain(&answer.authorities)
            .chain(&answer.additionals)
            .map(|record| {
                if is_opt(record) {
                    record.ttl
                } else {
                    record.ttl - 7
                }
            })
            .collect();
        assert_eq!(ttls(&hit), expected);
        hit
    }

    #[tokio::test]
    async fn golden_cname_chain_keeps_cnames_first_and_in_chain_order() {
        let mut answer = query_for_response("www.example.com");
        answer.header.recursion_available = true;
        answer.answers = vec![
            record(
                "www.example.com",
                RecordType::Cname,
                3600,
                RData::Cname(n("edge.cdn.example.net")),
            ),
            record(
                "edge.cdn.example.net",
                RecordType::Cname,
                300,
                RData::Cname(n("lb.cdn.example.net")),
            ),
            a_record("lb.cdn.example.net", 60, 7),
            a_record("lb.cdn.example.net", 60, 3),
            a_record("lb.cdn.example.net", 60, 5),
        ];

        let hit = assert_cache_hit_is_golden(answer).await;
        let types: Vec<_> = hit.answers.iter().map(|record| record.rtype).collect();
        assert_eq!(
            types,
            [
                RecordType::Cname,
                RecordType::Cname,
                RecordType::A,
                RecordType::A,
                RecordType::A
            ],
            "CNAME records stay ahead of the records they lead to"
        );
    }

    #[tokio::test]
    async fn golden_mixed_sections_keep_their_section_and_record_order() {
        let mut answer = query_for_response("example.com");
        answer.header.recursion_available = true;
        answer.answers = vec![
            a_record("example.com", 300, 2),
            a_record("example.com", 300, 1),
        ];
        answer.authorities = vec![
            record(
                "example.com",
                RecordType::Ns,
                3600,
                RData::Ns(n("ns2.example.com")),
            ),
            record(
                "example.com",
                RecordType::Ns,
                3600,
                RData::Ns(n("ns1.example.com")),
            ),
        ];
        answer.additionals = vec![
            a_record("ns2.example.com", 1800, 54),
            record(
                "ns2.example.com",
                RecordType::Aaaa,
                1800,
                RData::Aaaa("2001:db8::54".parse().unwrap()),
            ),
            a_record("ns1.example.com", 1800, 53),
        ];
        let mut edns = Edns::new(1232);
        edns.set_dnssec_ok(true);
        answer.set_edns(Some(edns));

        let hit = assert_cache_hit_is_golden(answer).await;
        assert!(is_opt(hit.additionals.last().unwrap()), "OPT stays last");
    }

    #[tokio::test]
    async fn golden_multi_record_rrsets_keep_their_order() {
        let mut answer = query_for_response("example.com");
        answer.questions[0].qtype = RecordType::Txt;
        answer.answers = vec![
            record(
                "example.com",
                RecordType::Txt,
                900,
                RData::Txt(vec![b"z-last-alphabetically".to_vec()]),
            ),
            record(
                "example.com",
                RecordType::Txt,
                900,
                RData::Txt(vec![b"a-first".to_vec(), b"second-string".to_vec()]),
            ),
            record(
                "example.com",
                RecordType::Txt,
                900,
                RData::Txt(vec![b"m-middle".to_vec()]),
            ),
        ];
        let query_type = RecordType::Txt;
        let (resolver, calls, clock) = cache_resolver(answer.clone());
        let query = query_for_type("example.com", query_type, Class::In, 1);
        assert_eq!(resolver.resolve(&query).await.unwrap(), answer);
        clock.advance(Duration::from_secs(7));
        let hit = resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(without_id_and_ttls(&hit), without_id_and_ttls(&answer));
        assert_eq!(
            without_id_and_ttls(&hit).encode().unwrap(),
            without_id_and_ttls(&answer).encode().unwrap()
        );
        assert_eq!(ttls(&hit), [893, 893, 893]);

        let mut a_rrset = query_for_response("example.com");
        a_rrset.answers = (1..=8)
            .rev()
            .map(|octet| a_record("example.com", 120, octet))
            .collect();
        assert_cache_hit_is_golden(a_rrset).await;
    }

    // --- EDNS(0): DO in the cache key, OPT never cached, alignment on every
    // `Ok` path ---------------------------------------------------------------

    use dns_lattice_model::EdnsOption;

    /// An A query for `name` carrying an OPT record advertising `payload`
    /// bytes with the given DO bit.
    fn edns_query_for(name: &str, payload: u16, dnssec_ok: bool) -> Message {
        let mut query = query_for(name);
        let mut edns = Edns::new(payload);
        edns.set_dnssec_ok(dnssec_ok);
        query.set_edns(Some(edns));
        query
    }

    /// An upstream OPT with a 4096-byte payload, the given DO bit and a
    /// per-transaction COOKIE option (code 10).
    fn upstream_edns(dnssec_ok: bool) -> Edns {
        let mut edns = Edns::new(4096);
        edns.set_dnssec_ok(dnssec_ok)
            .push_option(EdnsOption::new(10, vec![0xA5; 16]).unwrap());
        edns
    }

    #[tokio::test]
    async fn cache_hit_for_an_edns_query_gets_a_fresh_opt_with_the_do_bit_echoed() {
        let mut answer = a_answer("example.com", 300);
        answer.set_edns(Some(upstream_edns(true)));
        let (resolver, calls, clock) = cache_resolver(answer);
        let query = edns_query_for("example.com", 4096, true);

        let first = resolver.resolve(&query).await.unwrap();
        assert_eq!(
            first.edns().unwrap(),
            Some(upstream_edns(true)),
            "the fresh answer keeps the upstream OPT"
        );
        assert!(cache_holds_no_opt(&resolver));

        clock.advance(Duration::from_secs(5));
        let hit = resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "served from the cache");
        let mut expected = Edns::new(1232);
        expected.set_dnssec_ok(true);
        assert_eq!(hit.edns().unwrap(), Some(expected), "no upstream cookie");
        assert_eq!(
            hit.additionals
                .iter()
                .filter(|record| is_opt(record))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn non_edns_hit_on_an_entry_stored_from_an_edns_query_has_no_opt() {
        let mut answer = a_answer("example.com", 300);
        answer.set_edns(Some(upstream_edns(false)));
        let (resolver, calls, _clock) = cache_resolver(answer);

        resolver
            .resolve(&edns_query_for("example.com", 1232, false))
            .await
            .unwrap();
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "DO=0 shares the entry");
        assert_eq!(hit.edns().unwrap(), None);
        assert!(hit.additionals.is_empty());
    }

    #[tokio::test]
    async fn do_bit_splits_the_cache() {
        let (resolver, calls, _clock) = cache_resolver(a_answer("example.com", 300));
        let do_clear = edns_query_for("example.com", 1232, false);
        let do_set = edns_query_for("example.com", 1232, true);

        resolver.resolve(&do_clear).await.unwrap();
        resolver.resolve(&do_set).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "DO=0 and DO=1 are apart");
        let hit_clear = resolver.resolve(&do_clear).await.unwrap();
        let hit_set = resolver.resolve(&do_set).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "both are cached");
        assert!(!hit_clear.edns().unwrap().unwrap().dnssec_ok());
        assert!(hit_set.edns().unwrap().unwrap().dnssec_ok());
        assert_eq!(cache_len(&resolver), 2);
    }

    #[tokio::test]
    async fn extended_rcode_answer_to_an_edns_query_keeps_its_opt_and_is_not_cached() {
        let mut edns = Edns::new(4096);
        edns.set_extended_rcode(1);
        let mut answer = query_for_response("example.com");
        answer.set_edns(Some(edns.clone()));
        let (resolver, calls, _clock) = cache_resolver(answer);
        let query = edns_query_for("example.com", 1232, false);

        let first = resolver.resolve(&query).await.unwrap();
        assert_eq!(first.edns().unwrap(), Some(edns));
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache_len(&resolver), 0);
    }

    #[tokio::test]
    async fn fresh_answer_opt_is_removed_for_a_non_edns_query_and_replaced_when_malformed() {
        let mut answer = a_answer("example.com", 300);
        answer.set_edns(Some(upstream_edns(true)));
        let (resolver, _calls, _clock) = cache_resolver(answer);
        let fresh = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(fresh.edns().unwrap(), None, "a stray OPT is removed");
        assert!(fresh.additionals.is_empty());

        // A malformed upstream OPT (two OPT records) is replaced by a fresh
        // one for an EDNS query.
        let mut answer = a_answer("example.com", 300);
        answer.set_edns(Some(upstream_edns(false)));
        let opt = answer.additionals[0].clone();
        answer.additionals.push(opt);
        assert!(answer.edns().is_err());
        let (resolver, _calls, _clock) = cache_resolver(answer);
        let fresh = resolver
            .resolve(&edns_query_for("example.com", 1232, true))
            .await
            .unwrap();
        let mut expected = Edns::new(1232);
        expected.set_dnssec_ok(true);
        assert_eq!(fresh.edns().unwrap(), Some(expected));
    }

    #[tokio::test]
    async fn malformed_query_opt_leaves_the_answer_untouched() {
        let mut answer = a_answer("example.com", 300);
        answer.set_edns(Some(upstream_edns(true)));
        let (resolver, _calls, _clock) = cache_resolver(answer.clone());
        let mut query = edns_query_for("example.com", 1232, true);
        let opt = query.additionals[0].clone();
        query.additionals.push(opt);
        assert!(query.edns().is_err());

        let fresh = resolver.resolve(&query).await.unwrap();
        assert_eq!(fresh, answer, "passed through as in 1.1");
    }

    #[tokio::test]
    async fn fake_ip_answer_has_an_opt_exactly_when_the_query_has_one() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer: a_answer("example.test", 300),
                calls: calls.clone(),
            },
        )
        .fake_ip(
            fake_ip_pool(PoolClock::new()),
            fake_ip_policy("example.test"),
        )
        .build();

        let plain = resolver
            .resolve(&query_for("www.example.test"))
            .await
            .unwrap();
        assert_eq!(plain.answers.len(), 1);
        assert_eq!(plain.edns().unwrap(), None);

        let with_opt = resolver
            .resolve(&edns_query_for("www.example.test", 4096, true))
            .await
            .unwrap();
        assert_eq!(with_opt.answers.len(), 1);
        let mut expected = Edns::new(1232);
        expected.set_dnssec_ok(true);
        assert_eq!(with_opt.edns().unwrap(), Some(expected));
        assert_eq!(calls.load(Ordering::SeqCst), 0, "answered locally");
    }

    // --- Bounded store: CacheConfig, byte bound, clamps, concurrency. -------

    /// A resolver with one default group backed by a counting fake that
    /// always returns `answer`, on a fake clock, with `config` as its cache.
    fn configured_resolver(
        config: CacheConfig,
        answer: Message,
    ) -> (Resolver, Arc<AtomicUsize>, FakeClock) {
        let clock = FakeClock::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .clock(clock.clone())
        .cache(config)
        .backend(
            UpstreamGroupId::new("g"),
            CountingBackend {
                answer,
                calls: calls.clone(),
            },
        )
        .build();
        (resolver, calls, clock)
    }

    #[tokio::test]
    async fn a_disabled_cache_keeps_nothing_and_every_query_goes_upstream() {
        for config in [CacheConfig::disabled(), CacheConfig::new().max_bytes(0)] {
            let (resolver, calls, _clock) =
                configured_resolver(config, a_answer("example.com", 300));
            for _ in 0..3 {
                let answer = resolver.resolve(&query_for("example.com")).await.unwrap();
                assert_eq!(answer.answers.len(), 1);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert!(resolver.inner.cache.is_none());
        }
    }

    #[tokio::test]
    async fn the_default_cache_is_enabled() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::default(), a_answer("example.com", 300));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache_len(&resolver), 1);
    }

    #[tokio::test]
    async fn the_store_stays_within_its_byte_bound_while_names_flood_in() {
        let bound = 64 * 1024;
        let (resolver, calls, _clock) = configured_resolver(
            CacheConfig::new().max_bytes(bound).shards(1),
            a_answer("example.com", 300),
        );
        let store = resolver.inner.cache.as_ref().expect("enabled");
        let total = 500;
        for i in 0..total {
            resolver
                .resolve(&query_for(&format!("host{i}.example.com")))
                .await
                .unwrap();
            assert!(store.bytes() <= bound, "after {i}: {}", store.bytes());
        }
        assert_eq!(calls.load(Ordering::SeqCst), total);
        assert!(store.len() < total, "older entries were evicted");
        assert!(store.len() > 10, "the budget is actually used");
    }

    #[tokio::test]
    async fn an_answer_too_large_for_its_shard_is_returned_but_not_stored() {
        let mut answer = a_answer("example.com", 300);
        answer.answers[0].rtype = RecordType::Txt;
        answer.answers[0].rdata = RData::Txt(vec![vec![b'x'; 255]; 80]);
        let (resolver, calls, _clock) = configured_resolver(
            CacheConfig::new().max_bytes(64 * 1024).shards(1),
            answer.clone(),
        );
        let first = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(first.answers, answer.answers);
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "never cached");
        assert_eq!(cache_len(&resolver), 0);
    }

    #[tokio::test]
    async fn the_positive_ttl_bounds_are_configurable() {
        let config =
            CacheConfig::new().positive_ttl(Duration::from_secs(10), Duration::from_secs(60));
        // The maximum clamp.
        let (resolver, calls, clock) =
            configured_resolver(config.clone(), a_answer("example.com", 300));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        clock.advance(Duration::from_secs(59));
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(ttls(&hit), vec![1]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "gone at the clamped TTL");

        // The minimum clamp raises a short TTL.
        let (resolver, calls, clock) = configured_resolver(config, a_answer("example.com", 1));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        clock.advance(Duration::from_secs(9));
        let hit = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(ttls(&hit), vec![1]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn the_negative_ttl_bounds_are_configurable() {
        let config = CacheConfig::new().negative_ttl(Duration::ZERO, Duration::from_secs(30));
        let (resolver, calls, clock) =
            configured_resolver(config, nxdomain_answer("missing.example.com", Some(1_000)));
        let query = query_for("missing.example.com");
        resolver.resolve(&query).await.unwrap();
        clock.advance(Duration::from_secs(29));
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "clamped to 30 s");
    }

    #[tokio::test]
    async fn the_lifetime_of_a_negative_answer_without_soa_is_configurable() {
        let answer = nxdomain_answer("missing.example.com", None);
        let query = query_for("missing.example.com");

        let (resolver, calls, clock) = configured_resolver(
            CacheConfig::new().negative_ttl_without_soa(Some(Duration::from_secs(5))),
            answer.clone(),
        );
        resolver.resolve(&query).await.unwrap();
        clock.advance(Duration::from_secs(4));
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        clock.advance(Duration::from_secs(1));
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // `None` is strict RFC 2308: such an answer is not stored.
        let (resolver, calls, _clock) = configured_resolver(
            CacheConfig::new().negative_ttl_without_soa(None),
            answer.clone(),
        );
        resolver.resolve(&query).await.unwrap();
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache_len(&resolver), 0);

        // A negative answer that has an SOA is unaffected by the setting.
        let (resolver, calls, _clock) = configured_resolver(
            CacheConfig::new().negative_ttl_without_soa(None),
            nxdomain_answer("missing.example.com", Some(300)),
        );
        resolver.resolve(&query).await.unwrap();
        resolver.resolve(&query).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_hits_are_served_from_one_upstream_call() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::new().shards(4), a_answer("example.com", 300));
        let resolver = Arc::new(resolver);
        resolver.resolve(&query_for("example.com")).await.unwrap();

        let tasks: Vec<_> = (0..8_u16)
            .map(|task| {
                let resolver = Arc::clone(&resolver);
                tokio::spawn(async move {
                    for round in 0..100_u16 {
                        let mut query = query_for("example.com");
                        query.header.id = task * 1_000 + round;
                        let answer = resolver.resolve(&query).await.unwrap();
                        assert_eq!(answer.header.id, query.header.id);
                        assert_eq!(answer.answers.len(), 1);
                    }
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(resolver.inner.cache.as_ref().unwrap().all_unlocked());
    }

    #[tokio::test]
    async fn names_that_differ_only_in_case_share_one_entry() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::default(), a_answer("example.com", 300));
        resolver.resolve(&query_for("example.com")).await.unwrap();
        resolver.resolve(&query_for("EXAMPLE.com")).await.unwrap();
        resolver.resolve(&query_for("Example.COM.")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache_len(&resolver), 1);
    }

    // --- In-flight coalescing. ----------------------------------------------

    use crate::observability::CacheEvent;
    use tokio::sync::Semaphore;

    /// A fake backend that counts calls and holds each one until the test
    /// releases a permit, so a test controls exactly when the upstream query
    /// of a leader finishes. With `hang_first`, the first call never finishes
    /// (a leader that is later cancelled).
    struct GatedBackend {
        result: Result<Message>,
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        hang_first: bool,
    }

    #[async_trait]
    impl UpstreamBackend for GatedBackend {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hang_first && call == 0 {
                std::future::pending::<()>().await;
            }
            self.gate
                .acquire()
                .await
                .expect("gate is never closed")
                .forget();
            self.result.clone().map(|mut answer| {
                answer.header.id = query.header.id;
                answer
            })
        }
    }

    /// Both event streams of a sink, in arrival order per stream.
    #[derive(Default)]
    struct EventLog {
        observed: Mutex<Vec<ObserveEvent>>,
        cache: Mutex<Vec<CacheEvent>>,
    }

    impl ObservabilitySink for EventLog {
        fn record(&self, event: &ObserveEvent) {
            self.observed.lock().expect("poisoned").push(event.clone());
        }

        fn record_cache(&self, event: &CacheEvent) {
            self.cache.lock().expect("poisoned").push(event.clone());
        }
    }

    struct Gated {
        resolver: Resolver,
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        log: Arc<EventLog>,
    }

    fn gated_resolver(
        config: CacheConfig,
        result: Result<Message>,
        hang_first: bool,
        permits: usize,
    ) -> Gated {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(permits));
        let log = Arc::new(EventLog::default());
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .clock(FakeClock::new())
        .cache(config)
        .observability_sink(log.clone())
        .backend(
            UpstreamGroupId::new("g"),
            GatedBackend {
                result,
                calls: calls.clone(),
                gate: gate.clone(),
                hang_first,
            },
        )
        .build();
        Gated {
            resolver,
            calls,
            gate,
            log,
        }
    }

    fn query_with_id(name: &str, id: u16) -> Message {
        let mut query = query_for(name);
        query.header.id = id;
        query
    }

    /// Resolves `queries` concurrently on the current thread; once every one
    /// has been polled and is parked, releases `permits` upstream permits.
    /// Returns the results in query order.
    async fn resolve_together(
        gated: &Gated,
        queries: &[Message],
        permits: usize,
    ) -> Vec<Result<Message>> {
        let mut futures: Vec<_> = queries
            .iter()
            .map(|query| Box::pin(gated.resolver.resolve(query)))
            .collect();
        let mut results: Vec<Option<Result<Message>>> = queries.iter().map(|_| None).collect();
        // First round: every query runs until it parks, in order. The first
        // is the leader, the rest are followers (or, when bypassing, parked
        // in their own upstream call).
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            tokio::select! {
                biased;
                done = future.as_mut() => *result = Some(done),
                () = tokio::task::yield_now() => {}
            }
        }
        gated.gate.add_permits(permits);
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            if result.is_none() {
                *result = Some(future.await);
            }
        }
        results.into_iter().map(|r| r.expect("resolved")).collect()
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_upstream_call() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let queries: Vec<_> = (10..18)
            .map(|id| query_with_id("example.com", id))
            .collect();
        let results = resolve_together(&gated, &queries, 1).await;

        assert_eq!(gated.calls.load(Ordering::SeqCst), 1, "one upstream call");
        for (query, result) in queries.iter().zip(results) {
            let answer = result.unwrap();
            assert_eq!(answer.header.id, query.header.id, "own message id");
            assert_eq!(answer.questions, query.questions);
            assert_eq!(answer.answers.len(), 1);
            assert!(!answer.header.authoritative);
        }
        assert_eq!(cache_len(&gated.resolver), 1, "the answer was stored");
        assert_eq!(gated.resolver.inner.flights.as_ref().unwrap().len(), 0);
        // A later arrival hits the cache: the leader stored before unregistering.
        gated
            .resolver
            .resolve(&query_for("example.com"))
            .await
            .unwrap();
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn different_questions_do_not_coalesce() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let queries = [query_for("a.example.com"), query_for("b.example.com")];
        let results = resolve_together(&gated, &queries, 2).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(gated.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn coalescing_works_without_a_store_and_can_be_turned_off() {
        let queries: Vec<_> = (0..4).map(|id| query_with_id("example.com", id)).collect();

        let gated = gated_resolver(
            CacheConfig::disabled(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let results = resolve_together(&gated, &queries, 1).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache_len(&gated.resolver), 0);

        let gated = gated_resolver(
            CacheConfig::new().coalesce(false),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let results = resolve_together(&gated, &queries, 4).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            gated.calls.load(Ordering::SeqCst),
            4,
            "every miss goes upstream"
        );
        assert!(gated.log.cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_upstream_error_reaches_every_waiter_and_is_not_cached() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Err(Error::Transport("boom".to_owned())),
            false,
            0,
        );
        let queries: Vec<_> = (0..5).map(|id| query_with_id("example.com", id)).collect();
        let results = resolve_together(&gated, &queries, 1).await;
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
        for result in results {
            assert!(matches!(result, Err(Error::Transport(text)) if text == "boom"));
        }
        assert_eq!(cache_len(&gated.resolver), 0);
        assert_eq!(gated.resolver.inner.flights.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn an_answer_that_is_not_cacheable_still_fans_out() {
        let mut servfail = a_answer("example.com", 300);
        servfail.header.rcode = Rcode::ServFail;
        servfail.header.authoritative = true;
        let gated = gated_resolver(CacheConfig::new(), Ok(servfail), false, 0);
        let queries: Vec<_> = (0..3).map(|id| query_with_id("example.com", id)).collect();
        let results = resolve_together(&gated, &queries, 1).await;
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
        for (query, result) in queries.iter().zip(results) {
            let answer = result.unwrap();
            assert_eq!(answer.header.rcode, Rcode::ServFail);
            assert_eq!(answer.header.id, query.header.id);
            assert_eq!(ttls(&answer), vec![300], "TTL kept as received");
        }
        assert_eq!(cache_len(&gated.resolver), 0);
    }

    #[tokio::test]
    async fn a_cancelled_leader_hands_over_to_a_waiting_query() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            true,
            1,
        );
        let leader_query = query_with_id("example.com", 1);
        let waiter_query = query_with_id("example.com", 2);
        let mut leader = Box::pin(gated.resolver.resolve(&leader_query));
        let mut waiter = Box::pin(gated.resolver.resolve(&waiter_query));
        // The leader parks in its (hanging) upstream call, the waiter behind it.
        tokio::select! {
            biased;
            _ = leader.as_mut() => panic!("the first upstream call never completes"),
            _ = waiter.as_mut() => panic!("the waiter must wait for the leader"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
        assert_eq!(gated.resolver.inner.flights.as_ref().unwrap().len(), 1);

        drop(leader);
        assert_eq!(gated.resolver.inner.flights.as_ref().unwrap().len(), 0);
        let answer = waiter.await.unwrap();
        assert_eq!(answer.header.id, 2);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(gated.calls.load(Ordering::SeqCst), 2, "the waiter led");
        assert_eq!(cache_len(&gated.resolver), 1);
        assert_eq!(gated.resolver.inner.flights.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_new_leader_re_checks_the_cache_before_going_upstream() {
        let (resolver, calls, clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        let query = query_for("example.com");
        // Hold the flight as if a first leader were working on it.
        let key = KeyBuf::new(0, RecordType::A, Class::In, true, false, &n("example.com")).unwrap();
        let flights = resolver.inner.flights.as_ref().unwrap();
        let hash = flights.hash(key.as_bytes());
        let Join::Lead(first_leader) = flights.join_or_lead(hash, key.as_bytes()) else {
            panic!("the flight is free");
        };

        let mut waiter = Box::pin(resolver.resolve(&query));
        tokio::select! {
            biased;
            _ = waiter.as_mut() => panic!("the waiter must wait for the registered leader"),
            () = tokio::task::yield_now() => {}
        }
        // The first leader's answer lands in the store, then the leader is
        // cancelled without publishing.
        let store = resolver.inner.cache.as_ref().unwrap();
        let now = clock.now();
        let entry = cacheable_answer(
            &a_answer("example.com", 300),
            now,
            &resolver.inner.ttl_policy,
        )
        .expect("cacheable");
        assert!(store.insert(
            store.hash(key.as_bytes()),
            key.as_bytes(),
            Arc::new(entry),
            now
        ));
        drop(first_leader);

        let answer = waiter.await.unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "answered from the cache");
    }

    #[tokio::test]
    async fn a_purge_epoch_change_stops_a_stale_insert_but_not_the_answer() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let queries = [
            query_with_id("example.com", 1),
            query_with_id("example.com", 2),
        ];
        let mut futures: Vec<_> = queries
            .iter()
            .map(|query| Box::pin(gated.resolver.resolve(query)))
            .collect();
        for future in &mut futures {
            tokio::select! {
                biased;
                _ = future.as_mut() => panic!("blocked on the gate"),
                () = tokio::task::yield_now() => {}
            }
        }
        // A purge lands while the upstream query is in flight.
        gated
            .resolver
            .inner
            .cache_epoch
            .fetch_add(1, Ordering::SeqCst);
        gated.gate.add_permits(1);
        for future in futures {
            assert_eq!(
                future.await.unwrap().answers.len(),
                1,
                "waiters still answered"
            );
        }
        assert_eq!(
            cache_len(&gated.resolver),
            0,
            "the stale answer was not stored"
        );

        // After the purge, a fresh answer is stored again.
        gated.gate.add_permits(1);
        gated
            .resolver
            .resolve(&query_for("example.com"))
            .await
            .unwrap();
        assert_eq!(cache_len(&gated.resolver), 1);
        assert_eq!(gated.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_follower_emits_no_upstream_events_and_one_coalesced_event() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let queries = [
            query_with_id("example.com", 1),
            query_with_id("example.com", 2),
        ];
        resolve_together(&gated, &queries, 1).await;

        let observed = gated.log.observed.lock().unwrap().clone();
        let group = UpstreamGroupId::new("g");
        let of = |id: u64| -> Vec<ObserveEvent> {
            observed
                .iter()
                .filter(|event| event_id(event) == id)
                .cloned()
                .collect()
        };
        let leader = of(1);
        assert!(matches!(leader[0], ObserveEvent::QueryReceived { .. }));
        assert!(matches!(leader[1], ObserveEvent::StaticRoute { .. }));
        assert!(matches!(leader[2], ObserveEvent::CacheMiss { .. }));
        assert!(matches!(leader[3], ObserveEvent::UpstreamAttempt { .. }));
        assert!(matches!(leader[4], ObserveEvent::UpstreamOutcome { .. }));
        assert!(matches!(leader[5], ObserveEvent::Completed { .. }));

        let follower = of(2);
        assert_eq!(follower.len(), 4, "{follower:?}");
        assert!(matches!(follower[0], ObserveEvent::QueryReceived { .. }));
        assert!(matches!(follower[1], ObserveEvent::StaticRoute { .. }));
        assert!(matches!(follower[2], ObserveEvent::CacheMiss { .. }));
        assert!(matches!(follower[3], ObserveEvent::Completed { .. }));
        assert_eq!(
            *gated.log.cache.lock().unwrap(),
            vec![CacheEvent::Coalesced {
                correlation_id: 2,
                group,
            }]
        );
    }

    fn event_id(event: &ObserveEvent) -> u64 {
        match event {
            ObserveEvent::QueryReceived { correlation_id, .. }
            | ObserveEvent::FakeIpTerminal { correlation_id }
            | ObserveEvent::StaticRoute { correlation_id, .. }
            | ObserveEvent::HookDecision { correlation_id, .. }
            | ObserveEvent::CacheHit { correlation_id, .. }
            | ObserveEvent::CacheMiss { correlation_id, .. }
            | ObserveEvent::UpstreamAttempt { correlation_id, .. }
            | ObserveEvent::UpstreamOutcome { correlation_id, .. }
            | ObserveEvent::Completed { correlation_id, .. }
            | ObserveEvent::Failed { correlation_id, .. }
            | ObserveEvent::Cancelled { correlation_id } => *correlation_id,
        }
    }

    #[tokio::test]
    async fn a_follower_of_a_failed_leader_emits_failed() {
        let gated = gated_resolver(CacheConfig::new(), Err(Error::Timeout), false, 0);
        let queries = [
            query_with_id("example.com", 1),
            query_with_id("example.com", 2),
        ];
        resolve_together(&gated, &queries, 1).await;
        let observed = gated.log.observed.lock().unwrap().clone();
        let follower: Vec<_> = observed.iter().filter(|e| event_id(e) == 2).collect();
        assert!(matches!(
            follower.last(),
            Some(ObserveEvent::Failed {
                failure: ObserveFailure::Timeout,
                ..
            })
        ));
        assert!(
            !follower
                .iter()
                .any(|e| matches!(e, ObserveEvent::UpstreamAttempt { .. }))
        );
    }

    #[tokio::test]
    async fn a_panicking_sink_does_not_break_coalescing() {
        struct PanicsOnCache;
        impl ObservabilitySink for PanicsOnCache {
            fn record(&self, _: &ObserveEvent) {}
            fn record_cache(&self, _: &CacheEvent) {
                panic!("cache observer failure must be isolated");
            }
        }
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let mut resolver = gated.resolver;
        Arc::get_mut(&mut resolver.inner)
            .expect("the resolver is not shared")
            .observability_sink = Some(Arc::new(PanicsOnCache));
        let gated = Gated { resolver, ..gated };
        let queries = [
            query_with_id("example.com", 1),
            query_with_id("example.com", 2),
        ];
        let results = resolve_together(&gated, &queries, 1).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
    }

    fn query_with_option(name: &str, id: u16, code: u16) -> Message {
        let mut query = query_with_id(name, id);
        let mut edns = Edns::new(1232);
        edns.push_option(EdnsOption::new(code, vec![0, 1, 0, 0]).unwrap());
        query.set_edns(Some(edns));
        query
    }

    #[tokio::test]
    async fn ecs_and_unknown_option_queries_bypass_the_cache_and_coalescing() {
        for code in [8_u16, 65_001] {
            let gated = gated_resolver(
                CacheConfig::new(),
                Ok(a_answer("example.com", 300)),
                false,
                0,
            );
            let queries: Vec<_> = (0..3)
                .map(|id| query_with_option("example.com", id, code))
                .collect();
            let results = resolve_together(&gated, &queries, 3).await;
            assert!(results.iter().all(Result::is_ok), "option {code}");
            assert_eq!(
                gated.calls.load(Ordering::SeqCst),
                3,
                "option {code}: no coalescing"
            );
            assert_eq!(cache_len(&gated.resolver), 0, "option {code}: not stored");
            assert!(gated.log.cache.lock().unwrap().is_empty());

            // Nor is an earlier cached answer served to such a query.
            gated.gate.add_permits(2);
            gated
                .resolver
                .resolve(&query_for("example.com"))
                .await
                .unwrap();
            gated
                .resolver
                .resolve(&query_with_option("example.com", 9, code))
                .await
                .unwrap();
            assert_eq!(gated.calls.load(Ordering::SeqCst), 5, "option {code}");
        }
    }

    #[tokio::test]
    async fn nsid_cookie_keepalive_and_padding_options_stay_cacheable() {
        for code in [3_u16, 10, 11, 12] {
            let gated = gated_resolver(
                CacheConfig::new(),
                Ok(a_answer("example.com", 300)),
                false,
                0,
            );
            let queries: Vec<_> = (0..3)
                .map(|id| query_with_option("example.com", id, code))
                .collect();
            let results = resolve_together(&gated, &queries, 1).await;
            assert!(results.iter().all(Result::is_ok), "option {code}");
            assert_eq!(gated.calls.load(Ordering::SeqCst), 1, "option {code}");
            assert_eq!(cache_len(&gated.resolver), 1, "option {code}");
        }
    }

    #[test]
    fn query_uses_cache_follows_the_edns_option_rule() {
        assert!(query_uses_cache(&query_for("example.com")));
        assert!(query_uses_cache(&edns_query_for("example.com", 1232, true)));
        assert!(!query_uses_cache(&query_with_option("example.com", 1, 8)));
        assert!(query_uses_cache(&query_with_option("example.com", 1, 10)));
        let mut malformed = edns_query_for("example.com", 1232, true);
        let opt = malformed.additionals[0].clone();
        malformed.additionals.push(opt);
        assert!(malformed.edns().is_err());
        assert!(query_uses_cache(&malformed), "unchanged 1.1 behaviour");
    }

    #[test]
    fn parses_canonical_ipv4_and_ipv6_reverse_names() {
        assert_eq!(
            parse_reverse_name(&n("4.3.2.1.in-addr.arpa")),
            Some(std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(
            parse_reverse_name(&n("4.3.2.01.in-addr.arpa")),
            None,
            "non-canonical decimal labels are routed normally"
        );
        let reverse = format!("1.{}ip6.arpa", "0.".repeat(31));
        assert_eq!(
            parse_reverse_name(&n(&reverse)),
            Some(std::net::IpAddr::V6("::1".parse().unwrap()))
        );
    }

    // --- Flush, purge and statistics. ---------------------------------------

    /// Resolves each name once so the store holds one entry per name.
    async fn warm(resolver: &Resolver, names: &[&str]) {
        for name in names {
            resolver.resolve(&query_for(name)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn clear_cache_removes_everything_and_the_next_query_goes_upstream() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        warm(&resolver, &["a.example.com", "b.example.com", "c.net"]).await;
        assert_eq!(cache_len(&resolver), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        assert_eq!(resolver.clear_cache(), 3);
        assert_eq!(cache_len(&resolver), 0);
        assert_eq!(resolver.clear_cache(), 0, "nothing left to remove");
        assert_eq!(resolver.cache_stats().entries(), 0);
        assert_eq!(resolver.cache_stats().bytes(), 0);

        warm(&resolver, &["a.example.com"]).await;
        assert_eq!(calls.load(Ordering::SeqCst), 4, "refetched after the flush");
        assert_eq!(cache_len(&resolver), 1);
        assert!(resolver.inner.cache.as_ref().unwrap().all_unlocked());
    }

    #[tokio::test]
    async fn flushes_on_a_disabled_store_remove_nothing_and_do_not_panic() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::disabled(), a_answer("example.com", 300));
        warm(&resolver, &["example.com"]).await;
        assert_eq!(resolver.clear_cache(), 0);
        assert_eq!(resolver.purge(&n("example.com"), None), 0);
        assert_eq!(resolver.purge_subtree(&n("example.com")), 0);
        let stats = resolver.cache_stats();
        assert_eq!(
            (stats.entries(), stats.bytes(), stats.capacity_bytes()),
            (0, 0, 0)
        );
        assert_eq!((stats.hits(), stats.misses()), (0, 1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn purge_removes_one_name_across_types_classes_and_shapes() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        let mut no_rd = query_for("example.com");
        no_rd.header.recursion_desired = false;
        let queries = [
            query_for("example.com"),
            no_rd,
            edns_query_for("EXAMPLE.com", 1232, true),
            query_for_type("example.com", RecordType::Aaaa, Class::In, 1),
            query_for_type("example.com", RecordType::A, Class::Ch, 1),
            query_for("www.example.com"),
            query_for("example.org"),
        ];
        for query in &queries {
            resolver.resolve(query).await.unwrap();
        }
        let total = cache_len(&resolver);
        assert_eq!(total, 7);

        // One type only: the A entries of every shape and class... A in IN
        // with RD, without RD, with DO, and A in CH.
        assert_eq!(resolver.purge(&n("Example.Com."), Some(RecordType::A)), 4);
        assert_eq!(cache_len(&resolver), 3);
        // The AAAA entry, the subdomain and the other zone survive.
        let before = calls.load(Ordering::SeqCst);
        resolver
            .resolve(&query_for_type(
                "example.com",
                RecordType::Aaaa,
                Class::In,
                1,
            ))
            .await
            .unwrap();
        resolver
            .resolve(&query_for("www.example.com"))
            .await
            .unwrap();
        resolver.resolve(&query_for("example.org")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), before, "still cached");

        // Every type of the name.
        assert_eq!(resolver.purge(&n("example.com"), None), 1);
        assert_eq!(cache_len(&resolver), 2);
        assert_eq!(resolver.purge(&n("example.com"), None), 0, "already gone");
        assert_eq!(resolver.purge(&n("absent.example"), None), 0);
    }

    #[tokio::test]
    async fn purge_covers_every_upstream_group() {
        let group_g = UpstreamGroupId::new("g");
        let group_h = UpstreamGroupId::new("h");
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = |calls: &Arc<AtomicUsize>| CountingBackend {
            answer: a_answer("example.com", 300),
            calls: calls.clone(),
        };
        let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
            .clock(FakeClock::new())
            .route_hook(SequencedHook {
                decisions: Mutex::new(vec![
                    RouteDecision::Use(group_g.clone()),
                    RouteDecision::Use(group_h.clone()),
                    RouteDecision::Use(group_g),
                ]),
            })
            .backend(UpstreamGroupId::new("g"), backend(&calls))
            .backend(group_h, backend(&calls))
            .build();
        for _ in 0..2 {
            resolver.resolve(&query_for("example.com")).await.unwrap();
        }
        assert_eq!(cache_len(&resolver), 2, "one entry per group");

        assert_eq!(resolver.purge(&n("example.com"), None), 2);
        assert_eq!(cache_len(&resolver), 0);
        resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn purge_subtree_respects_label_boundaries() {
        let (resolver, _calls, _clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        let names = [
            "ample.com",
            "www.ample.com",
            "deep.www.ample.com",
            "example.com",
            "www.example.com",
            "ample.com.evil.org",
            "com",
        ];
        warm(&resolver, &names).await;
        assert_eq!(cache_len(&resolver), names.len());

        assert_eq!(resolver.purge_subtree(&n("AMPLE.com")), 3);
        assert_eq!(cache_len(&resolver), 4);
        // `example.com` and `www.example.com` were not touched by `ample.com`.
        assert_eq!(resolver.purge_subtree(&n("example.com")), 2);
        assert_eq!(resolver.purge_subtree(&n("com")), 1, "the apex itself");
        assert_eq!(resolver.purge_subtree(&n("ample.com")), 0);
        assert_eq!(cache_len(&resolver), 1);
        assert_eq!(resolver.purge_subtree(&n("org")), 1);
        assert_eq!(cache_len(&resolver), 0);
    }

    #[tokio::test]
    async fn purging_the_root_removes_everything() {
        let (resolver, _calls, _clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        warm(&resolver, &["a.example.com", "b.net", "c.org"]).await;
        assert_eq!(resolver.purge_subtree(&Name::root()), 3);
        assert_eq!(cache_len(&resolver), 0);
    }

    #[tokio::test]
    async fn a_flush_stops_in_flight_queries_from_storing_but_they_are_answered() {
        for flush in 0..3 {
            let gated = gated_resolver(
                CacheConfig::new(),
                Ok(a_answer("example.com", 300)),
                false,
                0,
            );
            let queries = [
                query_with_id("example.com", 1),
                query_with_id("example.com", 2),
            ];
            let mut futures: Vec<_> = queries
                .iter()
                .map(|query| Box::pin(gated.resolver.resolve(query)))
                .collect();
            for future in &mut futures {
                tokio::select! {
                    biased;
                    _ = future.as_mut() => panic!("blocked on the gate"),
                    () = tokio::task::yield_now() => {}
                }
            }
            match flush {
                0 => {
                    gated.resolver.clear_cache();
                }
                1 => {
                    gated.resolver.purge(&n("example.com"), None);
                }
                _ => {
                    gated.resolver.purge_subtree(&n("com"));
                }
            }
            gated.gate.add_permits(1);
            for future in futures {
                assert_eq!(future.await.unwrap().answers.len(), 1);
            }
            assert_eq!(cache_len(&gated.resolver), 0, "flush {flush}");
            assert_eq!(gated.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn cache_stats_count_hits_misses_inserts_and_expirations() {
        let (resolver, _calls, clock) =
            configured_resolver(CacheConfig::new().shards(1), a_answer("example.com", 300));
        let capacity = resolver.cache_stats().capacity_bytes();
        assert_eq!(capacity, 16 * 1024 * 1024);
        assert_eq!(
            resolver.cache_stats(),
            CacheStats {
                capacity_bytes: capacity,
                ..CacheStats::default()
            },
            "a new resolver has empty counters"
        );

        warm(&resolver, &["example.com"]).await; // miss + insert
        warm(&resolver, &["example.com"]).await; // hit
        warm(&resolver, &["example.com"]).await; // hit
        let stats = resolver.cache_stats();
        assert_eq!((stats.hits(), stats.misses(), stats.inserts()), (2, 1, 1));
        assert_eq!(stats.entries(), 1);
        assert!(stats.bytes() > 0 && stats.bytes() <= capacity);
        assert_eq!(stats.capacity_bytes(), capacity);
        assert_eq!((stats.evictions(), stats.expirations()), (0, 0));

        clock.advance(Duration::from_secs(300));
        warm(&resolver, &["example.com"]).await; // expired: miss + insert
        let stats = resolver.cache_stats();
        assert_eq!((stats.hits(), stats.misses(), stats.inserts()), (2, 2, 2));
        assert_eq!(stats.expirations(), 1);
        assert_eq!(stats.entries(), 1);

        // A flush empties the content but keeps the history.
        assert_eq!(resolver.clear_cache(), 1);
        let stats = resolver.cache_stats();
        assert_eq!((stats.entries(), stats.bytes()), (0, 0));
        assert_eq!((stats.hits(), stats.misses(), stats.inserts()), (2, 2, 2));
    }

    #[tokio::test]
    async fn cache_stats_count_evictions_and_oversized_answers() {
        let bound = 64 * 1024;
        let (resolver, _calls, _clock) = configured_resolver(
            CacheConfig::new().max_bytes(bound).shards(1),
            a_answer("example.com", 300),
        );
        for i in 0..500 {
            resolver
                .resolve(&query_for(&format!("host{i}.example.com")))
                .await
                .unwrap();
        }
        let stats = resolver.cache_stats();
        assert_eq!(stats.inserts(), 500);
        assert!(stats.evictions() > 0);
        assert_eq!(stats.inserts(), stats.entries() + stats.evictions());
        assert!(stats.bytes() <= stats.capacity_bytes());
        assert_eq!(stats.oversized_rejected(), 0);

        // An answer far above an eighth of the bound is returned, not stored.
        let mut big = a_answer("big.example.com", 300);
        big.answers[0].rdata = RData::Txt(vec![vec![b'x'; 255]; 200]);
        let (resolver, _calls, _clock) =
            configured_resolver(CacheConfig::new().max_bytes(bound).shards(1), big);
        resolver
            .resolve(&query_for("big.example.com"))
            .await
            .unwrap();
        let stats = resolver.cache_stats();
        assert_eq!(stats.oversized_rejected(), 1);
        assert_eq!((stats.entries(), stats.inserts()), (0, 0));
    }

    #[tokio::test]
    async fn cache_stats_count_coalesced_followers() {
        let gated = gated_resolver(
            CacheConfig::new(),
            Ok(a_answer("example.com", 300)),
            false,
            0,
        );
        let queries: Vec<_> = (0..4).map(|id| query_with_id("example.com", id)).collect();
        resolve_together(&gated, &queries, 1).await;
        let stats = gated.resolver.cache_stats();
        assert_eq!(stats.coalesced(), 3);
        assert_eq!(stats.misses(), 4);
        assert_eq!((stats.hits(), stats.inserts()), (0, 1));
    }

    #[tokio::test]
    async fn bypassing_queries_count_as_misses() {
        let (resolver, calls, _clock) =
            configured_resolver(CacheConfig::new(), a_answer("example.com", 300));
        for _ in 0..2 {
            resolver
                .resolve(&query_with_option("example.com", 1, 8))
                .await
                .unwrap();
        }
        let stats = resolver.cache_stats();
        assert_eq!((stats.hits(), stats.misses(), stats.entries()), (0, 2, 0));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // --- Prefetch. -----------------------------------------------------------

    use std::collections::VecDeque;

    /// Counts a backend call that has not finished (or been dropped) yet.
    struct InFlightGuard(Arc<AtomicUsize>);

    impl InFlightGuard {
        fn enter(counter: &Arc<AtomicUsize>) -> Self {
            counter.fetch_add(1, Ordering::SeqCst);
            InFlightGuard(Arc::clone(counter))
        }
    }

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A fake backend that plays a script of results (then 100 s answers for
    /// example.com), holds every call until the test releases a permit, and
    /// counts calls and calls still running.
    struct ScriptedBackend {
        script: Mutex<VecDeque<Result<Message>>>,
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        in_flight: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UpstreamBackend for ScriptedBackend {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _running = InFlightGuard::enter(&self.in_flight);
            self.gate
                .acquire()
                .await
                .expect("gate is never closed")
                .forget();
            let next = self.script.lock().expect("poisoned").pop_front();
            next.unwrap_or_else(|| Ok(a_answer("example.com", 100)))
                .map(|mut answer| {
                    answer.header.id = query.header.id;
                    answer
                })
        }
    }

    struct Prefetching {
        resolver: Resolver,
        calls: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        in_flight: Arc<AtomicUsize>,
        clock: FakeClock,
        log: Arc<EventLog>,
    }

    /// A resolver on a fake clock whose single backend plays `script`; the
    /// gate starts with one permit, for the first query.
    fn prefetching(config: CacheConfig, script: Vec<Result<Message>>) -> Prefetching {
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Semaphore::new(1));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let clock = FakeClock::new();
        let log = Arc::new(EventLog::default());
        let resolver = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(UpstreamGroupId::new("g"))
                .build(),
        )
        .clock(clock.clone())
        .cache(config)
        .observability_sink(log.clone())
        .backend(
            UpstreamGroupId::new("g"),
            ScriptedBackend {
                script: Mutex::new(script.into()),
                calls: calls.clone(),
                gate: gate.clone(),
                in_flight: in_flight.clone(),
            },
        )
        .build();
        Prefetching {
            resolver,
            calls,
            gate,
            in_flight,
            clock,
            log,
        }
    }

    /// Lets every spawned task run until it parks again (single thread, no
    /// timers, so a fixed number of yields is deterministic).
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn cache_events(p: &Prefetching) -> Vec<CacheEvent> {
        p.log.cache.lock().expect("poisoned").clone()
    }

    fn upstream_attempts(p: &Prefetching) -> usize {
        p.log
            .observed
            .lock()
            .expect("poisoned")
            .iter()
            .filter(|event| matches!(event, ObserveEvent::UpstreamAttempt { .. }))
            .count()
    }

    #[tokio::test]
    async fn a_popular_entry_is_refreshed_once_before_it_expires() {
        let p = prefetching(CacheConfig::new().prefetch(Some(Prefetch::new())), vec![]);
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap(); // stored at t=0, ttl 100
        p.clock.advance(secs(50));
        p.resolver.resolve(&query).await.unwrap(); // hit 1, outside the window
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.resolver.cache_stats().refreshes(), 0);

        p.clock.advance(secs(41)); // t=91: 9 s of 100 s remain
        p.gate.add_permits(1);
        let answer = p.resolver.resolve(&query).await.unwrap(); // hit 2
        assert_eq!(answer.answers[0].ttl, 9, "the hit is served from the cache");
        settle().await;

        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "one refresh");
        let stats = p.resolver.cache_stats();
        assert_eq!(stats.refreshes(), 1);
        assert_eq!((stats.hits(), stats.misses(), stats.inserts()), (2, 1, 2));
        let events = cache_events(&p);
        let [
            CacheEvent::RefreshStarted {
                correlation_id: started,
                group,
            },
            CacheEvent::RefreshCompleted {
                correlation_id: completed,
                refreshed: true,
                ..
            },
        ] = events.as_slice()
        else {
            panic!("unexpected cache events: {events:?}");
        };
        assert_eq!(started, completed);
        assert_eq!(group, &UpstreamGroupId::new("g"));
        assert_eq!(upstream_attempts(&p), 1, "a refresh emits no ObserveEvent");

        // The old entry would be gone at t=100; the refreshed one lives on.
        p.clock.advance(secs(9));
        let answer = p.resolver.resolve(&query).await.unwrap();
        assert_eq!(answer.answers[0].ttl, 91);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert_eq!(p.resolver.cache_stats().refreshes(), 1);
    }

    #[tokio::test]
    async fn prefetch_is_off_by_default() {
        let p = prefetching(CacheConfig::new(), vec![]);
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        for _ in 0..4 {
            p.resolver.resolve(&query).await.unwrap();
        }
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.resolver.cache_stats().refreshes(), 0);
        assert!(cache_events(&p).is_empty());
    }

    #[tokio::test]
    async fn min_hits_gates_the_refresh() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(5))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(91));
        for _ in 0..4 {
            p.resolver.resolve(&query).await.unwrap(); // hits 1..=4
        }
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 1, "too few hits");

        p.gate.add_permits(1);
        p.resolver.resolve(&query).await.unwrap(); // hit 5
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert_eq!(p.resolver.cache_stats().refreshes(), 1);
    }

    #[tokio::test]
    async fn threshold_percent_sets_the_window() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().threshold_percent(50).min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(49)); // 51 s remain: more than half
        p.resolver.resolve(&query).await.unwrap();
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);

        p.clock.advance(secs(1)); // exactly half remains
        p.gate.add_permits(1);
        p.resolver.resolve(&query).await.unwrap();
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_hits_start_a_single_refresh() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        // The refresh blocks in the backend: no permit yet.
        for id in 0..6 {
            p.resolver
                .resolve(&query_with_id("example.com", id))
                .await
                .unwrap();
        }
        settle().await;
        assert_eq!(
            p.calls.load(Ordering::SeqCst),
            2,
            "initial query + one refresh"
        );
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(p.resolver.cache_stats().refreshes(), 1);
        assert_eq!(cache_events(&p).len(), 1, "started, not completed");

        p.gate.add_permits(1);
        settle().await;
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(cache_events(&p).len(), 2);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_query_arriving_during_a_refresh_joins_it() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        p.resolver.resolve(&query).await.unwrap(); // starts the refresh
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);

        // The old entry has expired; the refresh is still running.
        p.clock.advance(secs(5));
        let joined = query_with_id("example.com", 77);
        let mut future = Box::pin(p.resolver.resolve(&joined));
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("must wait for the refresh"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "no second upstream call");
        assert_eq!(p.resolver.cache_stats().coalesced(), 1);

        p.gate.add_permits(1);
        let answer = future.await.unwrap();
        assert_eq!(answer.header.id, 77);
        assert_eq!(answer.answers[0].ttl, 95, "stored when the refresh began");
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert!(
            cache_events(&p)
                .iter()
                .any(|event| matches!(event, CacheEvent::Coalesced { .. }))
        );
    }

    #[tokio::test]
    async fn dropping_the_resolver_aborts_a_running_refresh() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        p.resolver.resolve(&query).await.unwrap();
        settle().await;
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 1, "refresh is running");

        let Prefetching {
            resolver,
            in_flight,
            gate,
            log,
            ..
        } = p;
        drop(resolver);
        settle().await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "the refresh was aborted"
        );
        gate.add_permits(1);
        settle().await;
        let events = log.cache.lock().expect("poisoned").clone();
        assert_eq!(events.len(), 1, "an aborted refresh never completes");
    }

    /// Polls `future` once with a no-op waker and no Tokio runtime.
    fn poll_ready<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("the fake backend answers immediately"),
        }
    }

    #[test]
    fn without_a_runtime_a_due_hit_neither_panics_nor_refreshes() {
        assert!(Handle::try_current().is_err(), "no runtime on this thread");
        let (resolver, calls, clock) = configured_resolver(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            a_answer("example.com", 100),
        );
        let query = query_for("example.com");
        poll_ready(resolver.resolve(&query)).unwrap();
        clock.advance(secs(95));
        for _ in 0..3 {
            let answer = poll_ready(resolver.resolve(&query)).unwrap();
            assert_eq!(answer.answers[0].ttl, 5);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.cache_stats().refreshes(), 0);
        assert!(lock(&resolver.background).is_empty());
    }

    #[tokio::test]
    async fn a_failed_refresh_leaves_the_entry_and_is_not_retried() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            vec![Ok(a_answer("example.com", 100)), Err(Error::Timeout)],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        p.gate.add_permits(1);
        p.resolver.resolve(&query).await.unwrap(); // starts the failing refresh
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            cache_events(&p).last(),
            Some(CacheEvent::RefreshCompleted {
                refreshed: false,
                ..
            })
        ));

        // The old entry still answers and no further refresh is attempted.
        p.clock.advance(secs(2));
        for _ in 0..3 {
            let answer = p.resolver.resolve(&query).await.unwrap();
            assert_eq!(answer.answers[0].ttl, 3);
        }
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert_eq!(p.resolver.cache_stats().refreshes(), 1);
    }

    #[tokio::test]
    async fn a_flush_during_a_refresh_stops_it_from_storing() {
        let p = prefetching(
            CacheConfig::new().prefetch(Some(Prefetch::new().min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        p.resolver.resolve(&query).await.unwrap();
        settle().await;
        assert_eq!(p.resolver.clear_cache(), 1);

        p.gate.add_permits(1);
        settle().await;
        assert_eq!(
            cache_len(&p.resolver),
            0,
            "the refreshed answer was not stored"
        );
        assert!(matches!(
            cache_events(&p).last(),
            Some(CacheEvent::RefreshCompleted {
                refreshed: false,
                ..
            })
        ));
        assert_eq!(p.resolver.inner.flights.as_ref().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn prefetch_needs_the_store() {
        let p = prefetching(
            CacheConfig::disabled().prefetch(Some(Prefetch::new().min_hits(0))),
            vec![],
        );
        p.gate.add_permits(2);
        for _ in 0..3 {
            p.resolver.resolve(&query_for("example.com")).await.unwrap();
        }
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        assert_eq!(p.resolver.cache_stats().refreshes(), 0);
        assert!(cache_events(&p).is_empty());
    }

    #[tokio::test]
    async fn refresh_without_coalescing_still_replaces_the_entry() {
        let p = prefetching(
            CacheConfig::new()
                .coalesce(false)
                .prefetch(Some(Prefetch::new().min_hits(1))),
            vec![],
        );
        let query = query_for("example.com");
        p.resolver.resolve(&query).await.unwrap();
        p.clock.advance(secs(95));
        p.gate.add_permits(1);
        p.resolver.resolve(&query).await.unwrap();
        settle().await;
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        p.clock.advance(secs(5));
        let answer = p.resolver.resolve(&query).await.unwrap();
        assert_eq!(answer.answers[0].ttl, 95);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    // --- Serve-stale and failure caching. ------------------------------------

    fn stale_config() -> CacheConfig {
        CacheConfig::new().serve_stale(Some(ServeStale::new()))
    }

    fn servfail_answer() -> Message {
        let mut msg = a_answer("example.com", 0);
        msg.answers.clear();
        msg.header.rcode = Rcode::ServFail;
        msg
    }

    fn first_ok() -> Result<Message> {
        Ok(a_answer("example.com", 100))
    }

    fn count_cache_events(p: &Prefetching, wanted: fn(&CacheEvent) -> bool) -> usize {
        cache_events(p).iter().filter(|event| wanted(event)).count()
    }

    fn is_stale_served(event: &CacheEvent) -> bool {
        matches!(event, CacheEvent::StaleServed { .. })
    }

    fn is_failure_served(event: &CacheEvent) -> bool {
        matches!(event, CacheEvent::FailureServed { .. })
    }

    fn count_observed(p: &Prefetching, wanted: fn(&ObserveEvent) -> bool) -> usize {
        p.log
            .observed
            .lock()
            .expect("poisoned")
            .iter()
            .filter(|event| wanted(event))
            .count()
    }

    fn is_cache_hit(event: &ObserveEvent) -> bool {
        matches!(event, ObserveEvent::CacheHit { .. })
    }

    /// Resolves `queries` together on the current thread; once all are parked
    /// at the gate, releases `permits`.
    async fn resolve_all(
        p: &Prefetching,
        queries: &[Message],
        permits: usize,
    ) -> Vec<Result<Message>> {
        let mut futures: Vec<_> = queries
            .iter()
            .map(|query| Box::pin(p.resolver.resolve(query)))
            .collect();
        let mut results: Vec<Option<Result<Message>>> = queries.iter().map(|_| None).collect();
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            tokio::select! {
                biased;
                done = future.as_mut() => *result = Some(done),
                () = tokio::task::yield_now() => {}
            }
        }
        p.gate.add_permits(permits);
        for (future, result) in futures.iter_mut().zip(results.iter_mut()) {
            if result.is_none() {
                *result = Some(future.await);
            }
        }
        results.into_iter().map(|r| r.expect("resolved")).collect()
    }

    #[tokio::test]
    async fn a_failed_refresh_serves_the_stale_answer() {
        let p = prefetching(stale_config(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);

        let answer = p
            .resolver
            .resolve(&query_with_id("example.com", 7))
            .await
            .unwrap();
        assert_eq!(answer.header.id, 7, "the caller's own id");
        assert_eq!(answer.questions, query_with_id("example.com", 7).questions);
        assert_eq!(answer.answers[0].ttl, 30, "stale reply TTL");
        assert_eq!(
            p.calls.load(Ordering::SeqCst),
            2,
            "the upstream was asked first"
        );
        assert_eq!(p.resolver.cache_stats().stale_hits(), 1);
        assert_eq!(count_cache_events(&p, is_stale_served), 1);
        assert!(
            answer.edns().unwrap().is_none(),
            "no OPT without a query OPT"
        );
    }

    #[tokio::test]
    async fn an_edns_client_gets_the_stale_answer_error() {
        let p = prefetching(
            stale_config(),
            vec![first_ok(), Err(Error::Transport("down".into()))],
        );
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);

        let answer = p
            .resolver
            .resolve(&edns_query_for("example.com", 1232, false))
            .await
            .unwrap();
        let edns = answer.edns().unwrap().expect("OPT present");
        let ede: Vec<_> = edns
            .options()
            .iter()
            .filter(|option| option.code() == 15)
            .collect();
        assert_eq!(ede.len(), 1);
        assert_eq!(ede[0].data(), &[0, 3], "info code 3, Stale Answer");
    }

    #[tokio::test]
    async fn queries_in_the_recheck_window_skip_the_upstream() {
        let p = prefetching(stale_config(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);
        p.resolver.resolve(&query_for("example.com")).await.unwrap(); // fails, marks
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        let hits_before = count_observed(&p, is_cache_hit);

        p.clock.advance(secs(10));
        for id in 0..3 {
            let answer = p
                .resolver
                .resolve(&query_with_id("example.com", id))
                .await
                .unwrap();
            assert_eq!(answer.header.id, id);
            assert_eq!(answer.answers[0].ttl, 30);
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "no upstream call");
        assert_eq!(
            count_observed(&p, is_cache_hit) - hits_before,
            3,
            "a cache hit"
        );
        assert_eq!(count_cache_events(&p, is_stale_served), 4);
        assert_eq!(p.resolver.cache_stats().stale_hits(), 4);

        // The window ends 30 s after the failure: the upstream is asked again
        // and a fresh answer replaces the entry.
        p.clock.advance(secs(20));
        p.gate.add_permits(1);
        let fresh = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        assert_eq!(fresh.answers[0].ttl, 100);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 3, "now a fresh hit");
    }

    #[tokio::test]
    async fn a_servfail_refresh_serves_stale_and_keeps_the_entry() {
        for rcode in [Rcode::ServFail, Rcode::Refused] {
            let mut failure = servfail_answer();
            failure.header.rcode = rcode;
            let p = prefetching(stale_config(), vec![first_ok(), Ok(failure)]);
            p.resolver.resolve(&query_for("example.com")).await.unwrap();
            p.clock.advance(secs(101));
            p.gate.add_permits(1);
            let answer = p.resolver.resolve(&query_for("example.com")).await.unwrap();
            assert_eq!(answer.header.rcode, Rcode::NoError, "{rcode:?}");
            assert_eq!(answer.answers[0].ttl, 30);
            assert_eq!(cache_len(&p.resolver), 1);
            assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn another_error_answer_is_returned_and_does_not_touch_the_stale_entry() {
        let mut formerr = servfail_answer();
        formerr.header.rcode = Rcode::FormErr;
        let p = prefetching(stale_config(), vec![first_ok(), Ok(formerr)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);
        let answer = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(answer.header.rcode, Rcode::FormErr);
        assert_eq!(p.resolver.cache_stats().stale_hits(), 0);
        assert_eq!(cache_len(&p.resolver), 1, "the stale entry is kept");

        // Not a failed refresh: no recheck window, the next query asks again.
        p.gate.add_permits(1);
        let fresh = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        assert_eq!(fresh.answers[0].ttl, 100);
    }

    #[tokio::test]
    async fn an_answer_older_than_max_stale_is_not_served() {
        let config = CacheConfig::new().serve_stale(Some(ServeStale::new().max_stale(secs(60))));
        let p = prefetching(
            config,
            vec![first_ok(), Err(Error::Timeout), Err(Error::Timeout)],
        );
        p.resolver.resolve(&query_for("example.com")).await.unwrap(); // expires at 100
        p.clock.advance(secs(150)); // 50 s stale
        p.gate.add_permits(1);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_ok());

        p.clock.advance(secs(20)); // 70 s stale: past max_stale (60 s)
        p.gate.add_permits(1);
        let result = p.resolver.resolve(&query_for("example.com")).await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(p.resolver.cache_stats().stale_hits(), 1);
    }

    #[tokio::test]
    async fn serve_stale_is_off_by_default() {
        let p = prefetching(CacheConfig::new(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);
        let result = p.resolver.resolve(&query_for("example.com")).await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(p.resolver.cache_stats().stale_hits(), 0);
        assert_eq!(cache_len(&p.resolver), 0, "nothing is retained");
    }

    #[tokio::test]
    async fn reply_ttl_and_failure_recheck_are_configurable() {
        let config = CacheConfig::new().serve_stale(Some(
            ServeStale::new()
                .reply_ttl(secs(5))
                .failure_recheck(secs(2)),
        ));
        let p = prefetching(config, vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);
        let answer = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(answer.answers[0].ttl, 5);

        p.clock.advance(secs(1));
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "still inside 2 s");
        p.clock.advance(secs(1));
        p.gate.add_permits(1);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 3, "window over");
    }

    #[tokio::test]
    async fn many_queries_on_a_stale_entry_cost_one_upstream_call() {
        let p = prefetching(stale_config(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));

        let queries: Vec<_> = (100..120)
            .map(|id| query_with_id("example.com", id))
            .collect();
        let results = resolve_all(&p, &queries, 1).await;
        assert_eq!(
            p.calls.load(Ordering::SeqCst),
            2,
            "one refresh for 20 queries"
        );
        for (query, result) in queries.iter().zip(results) {
            let answer = result.unwrap();
            assert_eq!(answer.header.id, query.header.id);
            assert_eq!(answer.answers[0].ttl, 30);
        }
        assert_eq!(p.resolver.cache_stats().stale_hits(), 20);
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 0);

        // A second batch inside the recheck window makes no call at all.
        let again: Vec<_> = (200..220)
            .map(|id| query_with_id("example.com", id))
            .collect();
        let results = resolve_all(&p, &again, 0).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert_eq!(p.resolver.cache_stats().stale_hits(), 40);
    }

    #[tokio::test]
    async fn stale_answers_are_per_cache_key() {
        let p = prefetching(stale_config(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(2);
        p.resolver.resolve(&query_for("example.com")).await.unwrap(); // stale
        // Another name has nothing stale: it goes upstream and is cached.
        let other = p
            .resolver
            .resolve(&query_for("other.example"))
            .await
            .unwrap();
        assert_eq!(other.answers[0].ttl, 100);
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        assert_eq!(cache_len(&p.resolver), 2);
    }

    // Failure caching.

    fn failure_config() -> CacheConfig {
        CacheConfig::new().failure_cache(Some(FailureCache::new()))
    }

    fn millis(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[tokio::test]
    async fn a_failure_is_served_without_an_upstream_call_until_its_backoff_ends() {
        let p = prefetching(
            failure_config(),
            vec![Err(Error::Timeout), Err(Error::Timeout)],
        );
        let first = p.resolver.resolve(&query_for("example.com")).await;
        assert!(matches!(first, Err(Error::Timeout)));
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);

        p.clock.advance(millis(500));
        let cached = p.resolver.resolve(&query_with_id("example.com", 9)).await;
        assert!(matches!(cached, Err(Error::Timeout)));
        assert_eq!(
            p.calls.load(Ordering::SeqCst),
            1,
            "served from the failure entry"
        );
        assert_eq!(p.resolver.cache_stats().failure_hits(), 1);
        assert_eq!(count_cache_events(&p, is_failure_served), 1);
        assert_eq!(count_observed(&p, is_cache_hit), 1);

        p.clock.advance(millis(500)); // 1 s: the first backoff is over
        p.gate.add_permits(1);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn consecutive_failures_back_off_exponentially_up_to_the_maximum() {
        let config = CacheConfig::new().failure_cache(Some(FailureCache::new().max(secs(4))));
        let p = prefetching(config, (0..8).map(|_| Err(Error::Timeout)).collect());
        let mut expected_calls = 0;
        // Each tuple is the backoff the failure just stored.
        for backoff in [1, 2, 4, 4] {
            p.gate.add_permits(1);
            assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
            expected_calls += 1;
            assert_eq!(p.calls.load(Ordering::SeqCst), expected_calls);

            p.clock.advance(secs(backoff) - millis(1));
            assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
            assert_eq!(
                p.calls.load(Ordering::SeqCst),
                expected_calls,
                "still cached after just under {backoff} s"
            );
            p.clock.advance(millis(1));
        }
        assert_eq!(p.resolver.cache_stats().failure_hits(), 4);
    }

    #[tokio::test]
    async fn a_success_resets_the_failure_backoff() {
        let p = prefetching(
            failure_config(),
            vec![
                Err(Error::Timeout),
                Err(Error::Timeout),
                first_ok(),
                Err(Error::Timeout),
            ],
        );
        for step in [1, 2] {
            p.gate.add_permits(1);
            assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
            p.clock.advance(secs(step)); // exactly the backoff just stored
        }
        p.gate.add_permits(1);
        p.resolver.resolve(&query_for("example.com")).await.unwrap(); // success
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        p.clock.advance(secs(101)); // the answer expires

        p.gate.add_permits(1);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
        assert_eq!(p.calls.load(Ordering::SeqCst), 4);
        // The backoff started over at 1 s, not 4 s.
        p.clock.advance(secs(1));
        p.gate.add_permits(1);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_ok());
        assert_eq!(p.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn a_cached_servfail_answer_carries_the_current_query_id() {
        let p = prefetching(failure_config(), vec![Ok(servfail_answer())]);
        let first = p
            .resolver
            .resolve(&query_with_id("example.com", 1))
            .await
            .unwrap();
        assert_eq!(first.header.rcode, Rcode::ServFail);

        let second = p
            .resolver
            .resolve(&query_with_id("example.com", 2))
            .await
            .unwrap();
        assert_eq!(second.header.rcode, Rcode::ServFail);
        assert_eq!(second.header.id, 2);
        assert_eq!(p.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.resolver.cache_stats().failure_hits(), 1);
    }

    #[tokio::test]
    async fn failure_caching_is_off_by_default() {
        let p = prefetching(
            CacheConfig::new(),
            vec![Err(Error::Timeout), Err(Error::Timeout)],
        );
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
        p.gate.add_permits(1);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
        assert_eq!(p.resolver.cache_stats().failure_hits(), 0);
        assert_eq!(cache_len(&p.resolver), 0);
    }

    #[tokio::test]
    async fn a_failure_does_not_affect_other_names() {
        let p = prefetching(failure_config(), vec![Err(Error::Timeout)]);
        assert!(p.resolver.resolve(&query_for("example.com")).await.is_err());
        p.gate.add_permits(1);
        let other = p
            .resolver
            .resolve(&query_for("other.example"))
            .await
            .unwrap();
        assert_eq!(other.header.rcode, Rcode::NoError);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_stale_entry_wins_over_failure_caching() {
        let config = stale_config().failure_cache(Some(FailureCache::new()));
        let p = prefetching(
            config,
            vec![first_ok(), Err(Error::Timeout), Err(Error::Timeout)],
        );
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1);
        let stale = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(stale.answers[0].ttl, 30);

        // After the recheck window the upstream is asked again and the stale
        // answer is still there: no failure entry replaced it.
        p.clock.advance(secs(31));
        p.gate.add_permits(1);
        let again = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(again.answers[0].ttl, 30);
        assert_eq!(p.calls.load(Ordering::SeqCst), 3);
        assert_eq!(p.resolver.cache_stats().failure_hits(), 0);
        assert_eq!(count_cache_events(&p, is_failure_served), 0);
    }

    #[tokio::test]
    async fn a_flush_during_the_call_stops_the_failure_from_being_stored() {
        let p = prefetching(failure_config(), vec![Err(Error::Timeout)]);
        p.gate.acquire().await.unwrap().forget(); // park the first call
        let query = query_for("example.com");
        let mut future = Box::pin(p.resolver.resolve(&query));
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("must park at the gate"),
            () = tokio::task::yield_now() => {}
        }
        p.resolver.clear_cache();
        p.gate.add_permits(1);
        assert!(future.await.is_err());
        assert_eq!(cache_len(&p.resolver), 0, "the stale epoch is not stored");

        p.gate.add_permits(1);
        p.resolver.resolve(&query).await.unwrap();
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    // Client timeout (Tokio paused time: the timer auto-advances when idle).

    fn timeout_config() -> CacheConfig {
        CacheConfig::new().serve_stale(Some(ServeStale::new().client_timeout(Some(millis(200)))))
    }

    #[tokio::test(start_paused = true)]
    async fn the_client_timeout_serves_stale_while_the_refresh_continues() {
        let p = prefetching(timeout_config(), vec![first_ok()]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101)); // stale; the gate has no permit

        let answer = p
            .resolver
            .resolve(&query_with_id("example.com", 5))
            .await
            .unwrap();
        assert_eq!(answer.header.id, 5);
        assert_eq!(answer.answers[0].ttl, 30);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "the refresh is running");
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(p.resolver.cache_stats().stale_hits(), 1);
        assert_eq!(
            upstream_attempts(&p),
            1,
            "the timed-out query made no attempt of its own"
        );
        assert!(
            cache_events(&p)
                .iter()
                .any(|event| matches!(event, CacheEvent::RefreshStarted { .. }))
        );

        p.gate.add_permits(1);
        settle().await;
        assert_eq!(p.in_flight.load(Ordering::SeqCst), 0);
        assert!(cache_events(&p).iter().any(|event| matches!(
            event,
            CacheEvent::RefreshCompleted {
                refreshed: true,
                ..
            }
        )));
        let fresh = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(fresh.answers[0].ttl, 100);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_that_fails_after_the_timeout_starts_the_recheck_window() {
        let p = prefetching(timeout_config(), vec![first_ok(), Err(Error::Timeout)]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.resolver.resolve(&query_for("example.com")).await.unwrap(); // timed out
        p.gate.add_permits(1);
        settle().await;
        assert!(cache_events(&p).iter().any(|event| matches!(
            event,
            CacheEvent::RefreshCompleted {
                refreshed: false,
                ..
            }
        )));

        let answer = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(answer.answers[0].ttl, 30);
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "the window holds");
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_queries_on_a_stale_entry_time_out_on_one_refresh() {
        let p = prefetching(timeout_config(), vec![first_ok()]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));

        let (q1, q2, q3) = (
            query_with_id("example.com", 1),
            query_with_id("example.com", 2),
            query_with_id("example.com", 3),
        );
        let (a, b, c) = tokio::join!(
            p.resolver.resolve(&q1),
            p.resolver.resolve(&q2),
            p.resolver.resolve(&q3),
        );
        for (id, result) in [(1, a), (2, b), (3, c)] {
            let answer = result.unwrap();
            assert_eq!(answer.header.id, id);
            assert_eq!(answer.answers[0].ttl, 30);
        }
        assert_eq!(p.calls.load(Ordering::SeqCst), 2, "one refresh");
        assert_eq!(p.resolver.cache_stats().stale_hits(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refresh_faster_than_the_timeout_returns_the_fresh_answer() {
        let p = prefetching(
            timeout_config(),
            vec![first_ok(), Ok(a_answer("example.com", 77))],
        );
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));
        p.gate.add_permits(1); // the refresh answers at once

        let answer = p.resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(answer.answers[0].ttl, 77);
        assert_eq!(p.resolver.cache_stats().stale_hits(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_client_timeout_needs_coalescing() {
        let config = timeout_config().coalesce(false);
        let p = prefetching(config, vec![first_ok()]);
        p.resolver.resolve(&query_for("example.com")).await.unwrap();
        p.clock.advance(secs(101));

        let query = query_for("example.com");
        let mut future = Box::pin(p.resolver.resolve(&query));
        tokio::select! {
            biased;
            _ = future.as_mut() => panic!("must wait for the upstream"),
            () = tokio::task::yield_now() => {}
        }
        p.gate.add_permits(1);
        let answer = future.await.unwrap();
        assert_eq!(
            answer.answers[0].ttl, 100,
            "waited inline for the fresh answer"
        );
        assert!(
            !cache_events(&p)
                .iter()
                .any(|event| matches!(event, CacheEvent::RefreshStarted { .. }))
        );
    }
}
