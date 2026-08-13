//! Query orchestration for decoded DNS messages.
//!
//! [`Resolver`] accepts a decoded [`Message`], selects an upstream group by
//! static [`SplitDnsPolicy`] routing, reads and writes its in-memory
//! TTL/negative cache, and invokes registered [`crate::upstream::UpstreamBackend`]
//! values in registration order with retryable-error failover.
//!
//! It does **not** own inbound server lifecycle, socket binding, wire
//! framing, TLS/HTTP/QUIC protocol handling, Fake IP allocation, dynamic
//! hooks, operating-system DNS configuration, or packet forwarding. Those
//! responsibilities belong respectively to [`crate::server`],
//! [`crate::upstream`], caller-invoked [`crate::fakeip`], future hook APIs,
//! and composing applications.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{
    Class, Message, Name, RData, Rcode, RecordType, SplitDnsPolicy, UpstreamGroupId,
};

use crate::upstream::UpstreamBackend;

/// Fixed negative-cache TTL floor (RFC 2308 §5) used when a negative
/// response carries no SOA record in its authority section to derive a
/// `minimum` from. It is not user-configurable.
const NEGATIVE_CACHE_FLOOR: Duration = Duration::from_secs(60);

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
/// independent of that struct's exact field set.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    rtype: RecordType,
    class: Class,
}

/// A cached answer plus its absolute expiry instant, computed at insert
/// time.
struct CacheEntry {
    answer: Message,
    expires_at: Instant,
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
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl Resolver {
    /// Starts building a resolver from a split-DNS policy.
    pub fn builder(policy: SplitDnsPolicy) -> ResolverBuilder {
        ResolverBuilder {
            policy,
            backends: HashMap::new(),
            clock: Box::new(SystemClock),
        }
    }

    /// Resolves one query.
    ///
    /// Extracts the queried name from `query`'s first question, checks the
    /// in-memory answer cache, and on a miss routes the query through the
    /// configured [`SplitDnsPolicy`] to select an upstream group, then tries
    /// that group's registered backends in registration order: the first
    /// backend to return `Ok` wins and its answer is
    /// cached (per the existing TTL rules) and returned immediately. A
    /// backend failing with [`Error::Timeout`], [`Error::Transport`], or
    /// [`Error::Tls`] is treated as retryable — resolution moves on to the
    /// next backend in the group rather than failing the whole call. Once
    /// every backend in the group has been tried and failed, the *last*
    /// attempted backend's error is propagated as-is; this exhausted-group
    /// failure is never cached. A group with exactly one backend behaves
    /// exactly as before: success or that one backend's own error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRoute`] when no split-DNS rule matches the
    /// queried name and no default upstream group is configured, when no
    /// question is present in `query`, or when the matched group has no
    /// backend registered. Returns the last attempted backend's error,
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
        let question = query.questions.first().ok_or(Error::NoRoute)?;
        let key = CacheKey {
            name: question.name.clone(),
            rtype: question.qtype,
            class: question.qclass,
        };

        let now = self.clock.now();
        {
            let cache = self.cache.lock().expect("cache mutex poisoned");
            if let Some(entry) = cache.get(&key)
                && entry.expires_at > now
            {
                return Ok(entry.answer.clone());
            }
        }

        let group = self
            .policy
            .resolve_group(&question.name)
            .ok_or(Error::NoRoute)?;
        let backends = self.backends.get(group).ok_or(Error::NoRoute)?;
        if backends.is_empty() {
            return Err(Error::NoRoute);
        }

        let mut last_err = None;
        for backend in backends {
            match backend.resolve(query).await {
                Ok(answer) => {
                    if let Some(ttl) = cacheable_ttl(&answer) {
                        let mut cache = self.cache.lock().expect("cache mutex poisoned");
                        cache.insert(
                            key,
                            CacheEntry {
                                answer: answer.clone(),
                                expires_at: now + ttl,
                            },
                        );
                    }
                    return Ok(answer);
                }
                Err(e) if is_retryable(&e) => {
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }

        Err(last_err.expect("at least one backend was tried since backends is non-empty"))
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

/// Determines the [`Duration`] an `answer` should be cached for, or `None`
/// if it should not be cached at all.
///
/// Positive answers (`NoError` with at least one answer record) use the
/// minimum `ttl` across their answer records. Negative
/// answers (`NxDomain`, or `NoError` with an empty answer section) use the
/// `minimum` field of an SOA record in the authority section when present
/// (RFC 2308 §5), else [`NEGATIVE_CACHE_FLOOR`].
fn cacheable_ttl(answer: &Message) -> Option<Duration> {
    let is_negative = matches!(answer.header.rcode, Rcode::NxDomain)
        || (matches!(answer.header.rcode, Rcode::NoError) && answer.answers.is_empty());

    if is_negative {
        let ttl = answer
            .authorities
            .iter()
            .find_map(|rr| match &rr.rdata {
                RData::Soa { minimum, .. } => Some(*minimum),
                _ => None,
            })
            .map(|minimum| Duration::from_secs(u64::from(minimum)))
            .unwrap_or(NEGATIVE_CACHE_FLOOR);
        return Some(ttl);
    }

    if answer.answers.is_empty() {
        return None;
    }

    answer
        .answers
        .iter()
        .map(|rr| rr.ttl)
        .min()
        .map(|ttl| Duration::from_secs(u64::from(ttl)))
}

/// Builds a [`Resolver`] from a split-DNS policy and one or more upstream
/// backends per group.
pub struct ResolverBuilder {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Vec<Box<dyn UpstreamBackend>>>,
    clock: Box<dyn Clock + Send + Sync>,
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dns_lattice_model::{RData, ResourceRecord};

    /// A configurable fake in-process [`UpstreamBackend`] that returns a
    /// fixed answer and counts how many times it was called, so cache-hit
    /// tests can assert the backend is *not* called again on a hit.
    struct CountingBackend {
        answer: Message,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl UpstreamBackend for CountingBackend {
        async fn resolve(&self, _query: &Message) -> Result<Message> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.answer.clone())
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
}
