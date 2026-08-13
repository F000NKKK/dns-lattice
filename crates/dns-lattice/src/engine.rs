//! Query orchestration for decoded DNS messages.
//!
//! [`Resolver`] accepts a decoded [`Message`], selects an upstream group by
//! static [`SplitDnsPolicy`] routing, reads and writes its in-memory
//! TTL/negative cache, and invokes registered [`crate::upstream::UpstreamBackend`]
//! values in registration order with retryable-error failover.
//!
//! It does **not** own inbound server lifecycle, socket binding, wire
//! framing, TLS/HTTP/QUIC protocol handling, dynamic hooks, operating-system
//! DNS configuration, or packet forwarding. Those responsibilities belong
//! respectively to [`crate::server`], [`crate::upstream`], future hook APIs,
//! and composing applications. When explicitly configured with a
//! [`crate::fakeip::FakeIpPool`] and [`crate::fakeip::FakeIpPolicy`], it does
//! orchestrate their local DNS answer synthesis; allocation and mapping
//! storage remain owned by the pool.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{
    Class, Message, Name, RData, Rcode, RecordType, ResourceRecord, SplitDnsPolicy, UpstreamGroupId,
};

use crate::fakeip::{FakeIpPolicy, FakeIpPool};
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
    fake_ip: Option<FakeIpResolverConfig>,
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

        if let Some(fake_ip) = &self.fake_ip
            && let Some(answer) = fake_ip_answer(query, fake_ip)?
        {
            return Ok(answer);
        }

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
    fake_ip: Option<FakeIpResolverConfig>,
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
