//! In-process resolver entry point: construct-from-config, resolve one
//! query, and route it via static split-DNS matching (stage 0.1's
//! [`SplitDnsPolicy`]) to an upstream group.
//!
//! Stage 0.2 also adds an in-memory, TTL-respecting answer cache including
//! negative caching (RFC 2308) — no real network transport yet (see
//! `ARCHITECTURE.md`'s stage sequencing). The upstream backend seam
//! (`UpstreamBackend`) is crate-private and intentionally minimal; it is not
//! a preview of the stage 0.3 public `upstream` trait.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{
    Class, Message, Name, RData, Rcode, RecordType, SplitDnsPolicy, UpstreamGroupId,
};

/// Fixed negative-cache TTL floor (RFC 2308 §5) used when a negative
/// response carries no SOA record in its authority section to derive a
/// `minimum` from. Not user-configurable in this stage (ADR-0010 point 4).
const NEGATIVE_CACHE_FLOOR: Duration = Duration::from_secs(60);

/// A source of the current time, abstracted so tests can advance it
/// deterministically instead of relying on real `sleep` (ADR-0010 point 5).
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
/// independent of that struct's exact field set (ADR-0010 point 1).
#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    rtype: RecordType,
    class: Class,
}

/// A cached answer plus its absolute expiry instant, computed at insert
/// time (ADR-0010 point 2).
struct CacheEntry {
    answer: Message,
    expires_at: Instant,
}

/// A synchronous, single-query seam between "which upstream group did
/// routing select" and "get an answer [`Message`] back".
///
/// Crate-private per ADR-0009: stage 0.2 resolves exactly one backend per
/// [`UpstreamGroupId`], with no failover across multiple backends within a
/// group. Stage 0.3 designs its own public `upstream` trait independently.
pub(crate) trait UpstreamBackend {
    /// Resolves `query` against this backend, returning the answer message
    /// or an error if the backend itself fails.
    fn resolve(&self, query: &Message) -> Result<Message>;
}

// Any `Fn(&Message) -> Result<Message>` is usable as an [`UpstreamBackend`],
// so [`ResolverBuilder::backend`] can accept a plain closure without ever
// naming the crate-private trait in its own (public) signature.
impl<F> UpstreamBackend for F
where
    F: Fn(&Message) -> Result<Message>,
{
    fn resolve(&self, query: &Message) -> Result<Message> {
        self(query)
    }
}

/// An in-process DNS resolver: construct from a split-DNS policy and one
/// upstream backend per group, then resolve queries against it.
///
/// # Lifecycle
///
/// Construct via [`Resolver::builder`], call [`Resolver::resolve`] as many
/// times as needed, then drop. This stage holds no background threads or
/// sockets, so there is no explicit `shutdown` method — Rust's ordinary drop
/// semantics fully release any resources the resolver owns.
pub struct Resolver {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Box<dyn UpstreamBackend + Send + Sync>>,
    clock: Box<dyn Clock + Send + Sync>,
    cache: RefCell<HashMap<CacheKey, CacheEntry>>,
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
    /// configured [`SplitDnsPolicy`] to select an upstream group and
    /// forwards it to that group's backend. Successful (positive or
    /// negative) answers are cached with a TTL-derived expiry; a cache hit
    /// never calls the backend again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRoute`] when no split-DNS rule matches the
    /// queried name and no default upstream group is configured, or when no
    /// question is present in `query`. Returns whatever error the selected
    /// backend produces, propagated as-is (not cached).
    pub fn resolve(&self, query: &Message) -> Result<Message> {
        let question = query.questions.first().ok_or(Error::NoRoute)?;
        let key = CacheKey {
            name: question.name.clone(),
            rtype: question.qtype,
            class: question.qclass,
        };

        let now = self.clock.now();
        if let Some(entry) = self.cache.borrow().get(&key)
            && entry.expires_at > now
        {
            return Ok(entry.answer.clone());
        }

        let group = self
            .policy
            .resolve_group(&question.name)
            .ok_or(Error::NoRoute)?;
        let backend = self.backends.get(group).ok_or(Error::NoRoute)?;
        let answer = backend.resolve(query)?;

        if let Some(ttl) = cacheable_ttl(&answer) {
            self.cache.borrow_mut().insert(
                key,
                CacheEntry {
                    answer: answer.clone(),
                    expires_at: now + ttl,
                },
            );
        }

        Ok(answer)
    }
}

/// Determines the [`Duration`] an `answer` should be cached for, or `None`
/// if it should not be cached at all.
///
/// Positive answers (`NoError` with at least one answer record) use the
/// minimum `ttl` across their answer records (ADR-0010 point 3). Negative
/// answers (`NxDomain`, or `NoError` with an empty answer section) use the
/// `minimum` field of an SOA record in the authority section when present
/// (RFC 2308 §5), else [`NEGATIVE_CACHE_FLOOR`] (ADR-0010 point 4).
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

/// Builds a [`Resolver`] from a split-DNS policy and one upstream backend
/// per group.
pub struct ResolverBuilder {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Box<dyn UpstreamBackend + Send + Sync>>,
    clock: Box<dyn Clock + Send + Sync>,
}

impl ResolverBuilder {
    /// Registers the upstream backend used to answer queries routed to
    /// `group`. A later call for the same `group` replaces the earlier
    /// registration.
    ///
    /// `backend` is a plain function/closure from a query [`Message`] to a
    /// resolved answer [`Message`]; stage 0.2 has no real transport, so this
    /// is how a fake in-process backend is wired in for testing.
    pub fn backend(
        mut self,
        group: UpstreamGroupId,
        backend: impl Fn(&Message) -> Result<Message> + Send + Sync + 'static,
    ) -> Self {
        self.backends.insert(group, Box::new(backend));
        self
    }

    /// Substitutes the clock used to compute and check cache expiry.
    /// Crate-private: no public API for clock injection in this stage
    /// (ADR-0010 point 5).
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
            cache: RefCell::new(HashMap::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{
        Class, DomainPattern, Header, Name, Opcode, Question, Rcode, RecordType,
    };

    /// A minimal test-only backend closure factory: always returns a fixed
    /// answer, proving wiring without modelling any real upstream behavior.
    fn fixed_backend(
        answer: Message,
    ) -> impl Fn(&Message) -> Result<Message> + Send + Sync + 'static {
        move |_query: &Message| Ok(answer.clone())
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

    #[test]
    fn routes_exact_match_to_its_group() {
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
            .expect("routed to corp backend");
        assert_eq!(answer.header.id, 42);
    }

    #[test]
    fn routes_suffix_match_to_its_group() {
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
            .expect("routed to corp backend via suffix");
        assert_eq!(answer.header.id, 7);
    }

    #[test]
    fn routes_wildcard_match_to_its_group() {
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
            .expect("routed to corp backend via wildcard");
        assert_eq!(answer.header.id, 9);
    }

    #[test]
    fn routes_unmatched_query_to_default_group() {
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
            .expect("routed to default group");
        assert_eq!(answer.header.id, 3);
    }

    #[test]
    fn no_route_when_no_match_and_no_default_group() {
        let policy = SplitDnsPolicy::builder().build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("example.com"))
            .expect_err("no rule and no default group configured");
        assert_eq!(err, Error::NoRoute);
    }

    #[test]
    fn no_route_when_matched_group_has_no_registered_backend() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect_err("matched group has no backend registered");
        assert_eq!(err, Error::NoRoute);
    }

    #[test]
    fn backend_error_propagates_as_is() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("corp"), |_query: &Message| {
                Err(Error::NameTooLong)
            })
            .build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect_err("backend failure propagates");
        assert_eq!(err, Error::NameTooLong);
    }

    // --- Dedicated fake upstream backend + cache test suite (deferred from
    // the routing slice, ADR-0009/ADR-0010) -------------------------------

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

    impl UpstreamBackend for CountingBackend {
        fn resolve(&self, _query: &Message) -> Result<Message> {
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
            .backend(UpstreamGroupId::new(group), move |query: &Message| {
                backend.resolve(query)
            })
            .build();
        (resolver, calls)
    }

    #[test]
    fn cache_hit_does_not_call_backend_again() {
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
            .expect("first resolve populates cache");
        let second = resolver
            .resolve(&query_for("example.com"))
            .expect("second resolve served from cache");

        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "backend called only once");
    }

    #[test]
    fn cache_entry_still_hit_just_before_ttl_elapses() {
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
            .expect("first resolve populates cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(299));

        resolver
            .resolve(&query_for("example.com"))
            .expect("still cached before ttl elapses");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "cache hit before expiry");
    }

    #[test]
    fn negative_answer_is_cached_with_soa_minimum_ttl() {
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
            .expect("nxdomain is Ok(Message), not Err");
        assert_eq!(first.header.rcode, Rcode::NxDomain);
        resolver
            .resolve(&query_for("missing.example.com"))
            .expect("served from negative cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "negative answer cached");
    }

    #[test]
    fn negative_answer_without_soa_uses_fixed_floor_ttl() {
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
            .expect("nxdomain without soa still Ok");
        resolver
            .resolve(&query_for("missing.example.com"))
            .expect("served from cache using the fixed floor ttl");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "negative answer cached via floor"
        );
    }

    #[test]
    fn nodata_answer_is_cached_as_negative() {
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
            .expect("nodata is Ok(Message)");
        resolver
            .resolve(&query_for("empty.example.com"))
            .expect("served from cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "nodata answer cached");
    }

    #[test]
    fn expired_cache_entry_triggers_a_fresh_backend_call() {
        let policy = SplitDnsPolicy::builder()
            .default_group(UpstreamGroupId::new("g"))
            .build();
        let clock = FakeClock::new();
        let (resolver, calls) =
            resolver_with_counting_backend(policy, "g", a_answer("example.com", 10), clock.clone());

        resolver
            .resolve(&query_for("example.com"))
            .expect("first resolve populates cache");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(11));

        resolver
            .resolve(&query_for("example.com"))
            .expect("expired entry re-queries the backend");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "ttl-expired entry is not served from cache"
        );
    }
}
