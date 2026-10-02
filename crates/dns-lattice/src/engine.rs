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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{
    Class, Edns, Message, Name, Opcode, RData, Rcode, RecordType, ResourceRecord, SplitDnsPolicy,
    UpstreamGroupId,
};

use crate::fakeip::{FakeIpPolicy, FakeIpPool};
use crate::hooks::{RouteDecision, RouteHook, RouteRequest};
use crate::observability::{
    HookObserveDecision, ObservabilitySink, ObserveEvent, ObserveFailure, UpstreamObserveOutcome,
};
use crate::upstream::{DEFAULT_EDNS_UDP_PAYLOAD_SIZE, UpstreamBackend};

/// Fixed negative-cache TTL, in seconds, used when a negative response
/// carries no SOA record in its authority section to derive one from. It is
/// capped by [`NEGATIVE_TTL`]'s maximum and is not user-configurable.
const NEGATIVE_TTL_WITHOUT_SOA: u32 = 60;

/// The `TYPE` value of the EDNS(0) OPT pseudo-record (RFC 6891). Its `TTL`
/// field holds the extended RCODE, version and flags, so it is never
/// clamped, counted down, or used to compute a cache lifetime.
const OPT_RTYPE: u16 = 41;

/// Inclusive bounds, in seconds, that every stored record TTL of one cache
/// entry class (positive or negative) is clamped into.
#[derive(Clone, Copy)]
struct TtlBounds {
    min: u32,
    max: u32,
}

impl TtlBounds {
    fn clamp(self, ttl: u32) -> u32 {
        ttl.clamp(self.min, self.max)
    }
}

/// Record TTL bounds for positive answers: at most one day.
const POSITIVE_TTL: TtlBounds = TtlBounds {
    min: 0,
    max: 86_400,
};

/// Record TTL bounds for negative answers (NXDOMAIN and NODATA): at most one
/// hour, following RFC 2308 §5's guidance.
const NEGATIVE_TTL: TtlBounds = TtlBounds { min: 0, max: 3_600 };

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

/// Cache key: the fields that identify a question's matching intent,
/// equivalent to a [`dns_lattice_model::Question`]'s name/type/class but
/// independent of that struct's exact field set, plus the effective upstream
/// group, the query's RD bit (an upstream may answer RD=0 and RD=1 queries
/// differently), and the query's EDNS DO bit (a DO=0 client must not receive
/// DNSSEC records cached for a DO=1 client, RFC 3225 §3).
#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    rtype: RecordType,
    class: Class,
    group: UpstreamGroupId,
    recursion_desired: bool,
    dnssec_ok: bool,
}

/// A normalised cached answer, shared through an [`Arc`] so a hit clones
/// only the pointer while the cache lock is held.
struct CachedAnswer {
    /// The upstream answer with its EDNS OPT record removed (OPT is
    /// per-transaction and never cached, RFC 6891 §6.1.1) and every record
    /// TTL clamped into the entry class's bounds (and, for a negative answer
    /// with an SOA, the SOA TTL rewritten to the negative TTL).
    message: Message,
    /// The instant captured before the upstream call; TTLs count down from
    /// here.
    inserted: Instant,
    /// `inserted` plus the entry TTL; the entry is a miss from this instant.
    expires: Instant,
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
/// times as needed, then drop. This stage holds no background threads, so
/// there is no explicit `shutdown` method — Rust's ordinary drop semantics
/// fully release any resources the resolver owns (including any sockets a
/// registered [`crate::upstream::UdpBackend`]/[`crate::upstream::TcpBackend`]
/// opens per call).
pub struct Resolver {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Vec<Box<dyn UpstreamBackend>>>,
    clock: Box<dyn Clock + Send + Sync>,
    cache: Mutex<HashMap<CacheKey, Arc<CachedAnswer>>>,
    fake_ip: Option<FakeIpResolverConfig>,
    route_hook: Option<Box<dyn RouteHook>>,
    observability_sink: Option<Arc<dyn ObservabilitySink>>,
    next_correlation_id: AtomicU64,
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
    /// A query uses the cache only when it has exactly one question and
    /// opcode `QUERY`; any other query goes straight to the upstream group
    /// (reported as a cache miss) and its answer is not stored. The cache
    /// identity is the question's name (case-insensitively), type and class,
    /// the effective upstream group, the query's RD bit, and the DO bit of
    /// the query's EDNS OPT record (false without a well-formed OPT).
    ///
    /// An answer is stored only when its opcode is `QUERY`, `TC` is clear,
    /// it carries either no EDNS OPT record or a well-formed one whose
    /// extended RCODE is 0, and it is either positive (`NOERROR` with at least one answer record)
    /// or negative (`NXDOMAIN`, or `NOERROR` with an empty answer section).
    /// `SERVFAIL`, `REFUSED` and every other response code are returned but
    /// never stored. The stored copy never keeps the EDNS OPT record. Before
    /// storing, every other record TTL is clamped to at most 86 400 s for a
    /// positive answer or 3 600 s for a negative one. The entry then lives
    /// for:
    ///
    /// - positive: the minimum record TTL over the answer, authority and
    ///   additional sections;
    /// - negative with an SOA in the authority section: min(SOA TTL, SOA
    ///   `MINIMUM`) (RFC 2308 §5), to which the stored SOA's TTL is
    ///   rewritten, or less if another record's TTL is lower;
    /// - negative without an SOA: 60 s, or less if a record's TTL is lower.
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

        let (group, backends) = match self.select_backends(question, correlation_id).await {
            Ok(selected) => selected,
            Err(error) => {
                self.emit(ObserveEvent::Failed {
                    correlation_id,
                    failure: observe_failure(&error),
                });
                return Err(error);
            }
        };
        let mut key = query_uses_cache(query).then(|| CacheKey {
            name: question.name.clone(),
            rtype: question.qtype,
            class: question.qclass,
            group: group.clone(),
            recursion_desired: query.header.recursion_desired,
            dnssec_ok: query_dnssec_ok(query),
        });

        let now = self.clock.now();
        if let Some(cached) = key.as_ref().and_then(|key| self.cache_lookup(key, now)) {
            let mut answer = cache_hit_response(query, &cached, now);
            align_edns(query, &mut answer);
            self.emit(ObserveEvent::CacheHit {
                correlation_id,
                group: group.clone(),
            });
            self.emit(ObserveEvent::Completed {
                correlation_id,
                rcode: answer.header.rcode,
            });
            return Ok(answer);
        }
        self.emit(ObserveEvent::CacheMiss {
            correlation_id,
            group: group.clone(),
        });

        let mut last_err = None;
        for (backend_index, backend) in backends.iter().enumerate() {
            self.emit(ObserveEvent::UpstreamAttempt {
                correlation_id,
                group: group.clone(),
                backend_index,
            });
            match backend.resolve(query).await {
                Ok(mut answer) => {
                    self.emit(ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::Success,
                    });
                    if let Some(key) = key.take()
                        && let Some(entry) = cacheable_answer(&answer, now)
                    {
                        let entry = Arc::new(entry);
                        self.cache
                            .lock()
                            .expect("cache mutex poisoned")
                            .insert(key, entry);
                    }
                    align_edns(query, &mut answer);
                    self.emit(ObserveEvent::Completed {
                        correlation_id,
                        rcode: answer.header.rcode,
                    });
                    return Ok(answer);
                }
                Err(e) if is_retryable(&e) => {
                    self.emit(ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::RetryableFailure,
                    });
                    last_err = Some(e);
                }
                Err(e) => {
                    self.emit(ObserveEvent::UpstreamOutcome {
                        correlation_id,
                        group: group.clone(),
                        backend_index,
                        outcome: UpstreamObserveOutcome::Failure,
                    });
                    self.emit(ObserveEvent::Failed {
                        correlation_id,
                        failure: observe_failure(&e),
                    });
                    return Err(e);
                }
            }
        }

        let error = last_err.expect("at least one backend was tried since backends is non-empty");
        self.emit(ObserveEvent::Failed {
            correlation_id,
            failure: observe_failure(&error),
        });
        Err(error)
    }

    fn emit(&self, event: ObserveEvent) {
        if let Some(sink) = &self.observability_sink {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.record(&event)));
        }
    }

    /// Returns the fresh entry for `key`, cloning only its [`Arc`] under the
    /// cache lock. An entry found expired at `now` is removed.
    fn cache_lookup(&self, key: &CacheKey, now: Instant) -> Option<Arc<CachedAnswer>> {
        let mut cache = self.cache.lock().expect("cache mutex poisoned");
        match cache.get(key) {
            Some(entry) if entry.expires > now => Some(Arc::clone(entry)),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    /// Selects and validates the effective upstream group for one ordinary
    /// query. This deliberately happens before the cache lookup because a
    /// hook may choose different groups for equal DNS questions.
    ///
    /// No resolver mutex is held while invoking the hook. Dropping the
    /// enclosing [`Resolver::resolve`] future drops this in-flight hook call;
    /// hook implementations own cancellation cleanup and must not re-enter
    /// this resolver.
    async fn select_backends(
        &self,
        question: &dns_lattice_model::Question,
        correlation_id: u64,
    ) -> Result<(UpstreamGroupId, &Vec<Box<dyn UpstreamBackend>>)> {
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
        Ok((group, backends))
    }
}

/// Whether `query` may be answered from, and stored in, the cache: exactly
/// one question and opcode `QUERY`.
fn query_uses_cache(query: &Message) -> bool {
    query.questions.len() == 1 && query.header.opcode == Opcode::Query
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
/// The stored copy has its OPT record removed. Every remaining record TTL is clamped into [`POSITIVE_TTL`] or
/// [`NEGATIVE_TTL`]. The entry TTL is the minimum non-OPT record TTL over
/// all sections. For a negative answer it is further limited to the
/// negative TTL: min(SOA TTL, SOA `MINIMUM`) (RFC 2308 §5) clamped into
/// [`NEGATIVE_TTL`], written back to the first authority SOA's TTL so it
/// counts down on hits (RFC 2308 §6), or [`NEGATIVE_TTL_WITHOUT_SOA`]
/// (clamped likewise) when the authority section has no SOA. An entry TTL
/// of 0 is not stored. `inserted` anchors the countdown and expiry.
fn cacheable_answer(answer: &Message, inserted: Instant) -> Option<CachedAnswer> {
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
    let bounds = if negative { NEGATIVE_TTL } else { POSITIVE_TTL };

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
            None => bounds.clamp(NEGATIVE_TTL_WITHOUT_SOA),
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
    Some(CachedAnswer {
        message,
        inserted,
        expires: inserted + Duration::from_secs(u64::from(ttl)),
    })
}

/// Builds a [`Resolver`] from a split-DNS policy and one or more upstream
/// backends per group.
pub struct ResolverBuilder {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Vec<Box<dyn UpstreamBackend>>>,
    clock: Box<dyn Clock + Send + Sync>,
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

    /// Substitutes the clock used to compute and check cache expiry.
    /// Crate-private: no public API for clock injection.
    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Clock + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> Resolver {
        Resolver {
            policy: self.policy,
            backends: self.backends,
            clock: self.clock,
            cache: Mutex::new(HashMap::new()),
            fake_ip: self.fake_ip,
            route_hook: self.route_hook,
            observability_sink: self.observability_sink,
            next_correlation_id: AtomicU64::new(1),
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
        let resolver = ResolverBuilder {
            policy: base.policy,
            backends: base.backends,
            clock: base.clock,
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
                resolver
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
        assert!(resolver.cache.lock().unwrap().is_empty());
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
            resolver.cache.try_lock().is_ok(),
            "the resolver cache mutex is not held across hook await"
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
            .cache
            .lock()
            .unwrap()
            .values()
            .all(|entry| entry.message.edns() == Ok(None))
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
        assert!(flagged.additionals[0].ttl > POSITIVE_TTL.max);
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
            assert!(resolver.cache.lock().unwrap().is_empty(), "{label}");
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
        assert!(resolver.cache.lock().unwrap().is_empty());
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
        assert_eq!(resolver.cache.lock().unwrap().len(), 1);
        clock.advance(Duration::from_secs(10));
        let refreshed = resolver.resolve(&query_for("example.com")).await.unwrap();
        assert_eq!(refreshed.header.rcode, Rcode::ServFail);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            resolver.cache.lock().unwrap().is_empty(),
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
        assert_eq!(resolver.cache.lock().unwrap().len(), 2);
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
        assert!(resolver.cache.lock().unwrap().is_empty());
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
}
