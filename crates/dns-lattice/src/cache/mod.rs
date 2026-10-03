//! Resolver answer-cache configuration.
//!
//! [`crate::engine::Resolver`] keeps an in-memory cache of upstream answers.
//! The cache is a sharded, byte-bounded store: its memory use is limited by
//! [`CacheConfig::max_bytes`] and the limit is enforced on every insert, by
//! evicting entries one at a time. Expired entries are evicted first, then
//! entries that were never reused, so a flood of one-off names cannot push
//! out the names that are asked for repeatedly. The cache is never flushed
//! as a whole to make room.
//!
//! Concurrent misses for the same question share one upstream query; see
//! [`CacheConfig::coalesce`].
//!
//! The cache can be flushed with [`crate::engine::Resolver::clear_cache`],
//! [`crate::engine::Resolver::purge`] and
//! [`crate::engine::Resolver::purge_subtree`] and observed through
//! [`crate::engine::Resolver::cache_stats`] ([`CacheStats`]).
//!
//! Configure it through [`crate::engine::ResolverBuilder::cache`]:
//!
//! ```
//! use std::time::Duration;
//!
//! use dns_lattice::cache::CacheConfig;
//! use dns_lattice::engine::Resolver;
//! use dns_lattice::model::SplitDnsPolicy;
//!
//! let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
//!     .cache(
//!         CacheConfig::new()
//!             .max_bytes(4 * 1024 * 1024)
//!             .positive_ttl(Duration::from_secs(5), Duration::from_secs(3_600)),
//!     )
//!     .build();
//! # let _ = resolver;
//! ```

use std::time::Duration;

pub(crate) mod flight;
pub(crate) mod store;

/// Default memory bound of the answer store: 16 MiB (estimated).
const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Largest positive record TTL kept by default: one day.
const DEFAULT_POSITIVE_MAX: u32 = 86_400;

/// Largest negative record TTL kept by default: one hour.
const DEFAULT_NEGATIVE_MAX: u32 = 3_600;

/// Negative-cache lifetime, in seconds, for a negative answer that carries no
/// SOA record to derive one from.
const DEFAULT_NEGATIVE_WITHOUT_SOA: u32 = 60;

/// Smallest accepted explicit shard count.
const MIN_SHARDS: usize = 1;

/// Largest accepted explicit shard count.
const MAX_SHARDS: usize = 1024;

/// Inclusive bounds, in seconds, that every stored record TTL of one cache
/// entry class (positive or negative) is clamped into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TtlBounds {
    min: u32,
    max: u32,
}

impl TtlBounds {
    /// Bounds from whole seconds; `max` is raised to `min` when smaller.
    fn new(min: Duration, max: Duration) -> Self {
        let min = whole_seconds(min);
        let max = whole_seconds(max).max(min);
        TtlBounds { min, max }
    }

    /// Clamps `ttl` into the bounds.
    pub(crate) fn clamp(self, ttl: u32) -> u32 {
        ttl.clamp(self.min, self.max)
    }
}

/// The TTL rules applied when an answer is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TtlPolicy {
    /// Bounds for positive answers.
    pub(crate) positive: TtlBounds,
    /// Bounds for negative answers (NXDOMAIN and NODATA).
    pub(crate) negative: TtlBounds,
    /// Lifetime of a negative answer without an SOA; `None` stores no such
    /// answer.
    pub(crate) negative_without_soa: Option<u32>,
}

/// Whole seconds of `duration`, saturating at [`u32::MAX`].
fn whole_seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
}

/// Configuration of a [`crate::engine::Resolver`]'s answer cache.
///
/// [`CacheConfig::new`] (also [`Default`]) describes the defaults: a store
/// bounded to 16 MiB, positive record TTLs clamped to 0 s..=86 400 s,
/// negative ones to 0 s..=3 600 s, and a 60 s lifetime for a negative answer
/// without an SOA record. Use [`CacheConfig::disabled`] to turn the store off.
///
/// The byte bound is an estimate of the heap an entry occupies (a structural
/// sum over its key, records and names plus fixed bookkeeping), not an
/// allocator-exact figure. It is enforced on every insert, per shard: each
/// shard owns an equal share of the limit and evicts on its own.
///
/// ```
/// use std::time::Duration;
///
/// use dns_lattice::cache::CacheConfig;
///
/// let config = CacheConfig::new()
///     .max_bytes(1024 * 1024)
///     .negative_ttl(Duration::ZERO, Duration::from_secs(300))
///     .negative_ttl_without_soa(None);
/// # let _ = config;
/// ```
#[derive(Debug, Clone)]
pub struct CacheConfig {
    max_bytes: usize,
    shards: Option<usize>,
    positive: TtlBounds,
    negative: TtlBounds,
    negative_without_soa: Option<u32>,
    coalesce: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig::new()
    }
}

impl CacheConfig {
    /// The default configuration: 16 MiB (estimated) store with an automatic
    /// shard count, positive record TTLs 0 s..=86 400 s, negative record TTLs
    /// 0 s..=3 600 s, and 60 s for a negative answer without an SOA record.
    pub fn new() -> Self {
        CacheConfig {
            max_bytes: DEFAULT_MAX_BYTES,
            shards: None,
            positive: TtlBounds {
                min: 0,
                max: DEFAULT_POSITIVE_MAX,
            },
            negative: TtlBounds {
                min: 0,
                max: DEFAULT_NEGATIVE_MAX,
            },
            negative_without_soa: Some(DEFAULT_NEGATIVE_WITHOUT_SOA),
            coalesce: true,
        }
    }

    /// A configuration with no answer store: every query goes to its
    /// upstream group and nothing is kept. Concurrent identical queries are
    /// still coalesced unless [`CacheConfig::coalesce`] turns that off.
    pub fn disabled() -> Self {
        CacheConfig::new().max_bytes(0)
    }

    /// Sets the memory bound of the store in (estimated) bytes. `0` disables
    /// the store, like [`CacheConfig::disabled`].
    ///
    /// The bound is split equally between the shards. An answer whose
    /// estimated size exceeds one eighth of its shard's share is never
    /// stored, so a bound far below the default also stops large answers
    /// from being cached.
    #[must_use]
    pub fn max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// Sets the number of shards, rounded up to a power of two and limited to
    /// `1..=1024`. Each shard has its own lock; more shards reduce contention
    /// between concurrent queries but give each shard a smaller share of
    /// [`CacheConfig::max_bytes`].
    ///
    /// Without this call the count is derived from the available parallelism
    /// (four shards per core, at most 64) and reduced so every shard keeps at
    /// least 256 KiB.
    #[must_use]
    pub fn shards(mut self, shards: usize) -> Self {
        self.shards = Some(shards.clamp(MIN_SHARDS, MAX_SHARDS).next_power_of_two());
        self
    }

    /// Sets the inclusive TTL bounds, in whole seconds, that every record of
    /// a positive answer is clamped into before storing. A `max` below `min`
    /// is raised to `min`.
    ///
    /// A `min` above zero keeps answers longer than their upstream asked
    /// for, which RFC 2181 does not sanction; use it deliberately.
    #[must_use]
    pub fn positive_ttl(mut self, min: Duration, max: Duration) -> Self {
        self.positive = TtlBounds::new(min, max);
        self
    }

    /// Sets the inclusive TTL bounds, in whole seconds, that every record of
    /// a negative answer (`NXDOMAIN` or `NODATA`) is clamped into before
    /// storing. A `max` below `min` is raised to `min`.
    #[must_use]
    pub fn negative_ttl(mut self, min: Duration, max: Duration) -> Self {
        self.negative = TtlBounds::new(min, max);
        self
    }

    /// Sets how long a negative answer without an SOA record in its
    /// authority section is kept (whole seconds, clamped into the negative
    /// bounds). `None` does not store such answers, which is the strict
    /// reading of RFC 2308 §5. The default is 60 s.
    #[must_use]
    pub fn negative_ttl_without_soa(mut self, ttl: Option<Duration>) -> Self {
        self.negative_without_soa = ttl.map(whole_seconds);
        self
    }

    /// Turns in-flight query coalescing on or off. It is on by default.
    ///
    /// With coalescing, concurrent cache misses for the same cache identity
    /// share one upstream query: the first caller queries, the others wait
    /// for its result and are answered from it, emitting no upstream events
    /// of their own. If the first caller is cancelled (its `resolve` future
    /// is dropped), one of the waiting callers takes over, so no caller is
    /// left without an answer and nothing is spawned. A waiting caller also
    /// receives an upstream error, or an answer that is not cacheable (such
    /// as `SERVFAIL`), exactly as the first caller did.
    ///
    /// Queries that bypass the cache are never coalesced: more or fewer than
    /// one question, an opcode other than `QUERY`, an EDNS Client Subnet
    /// option, or any EDNS option other than NSID, COOKIE, TCP keepalive and
    /// Padding. With `false`, every miss queries its upstream group itself.
    #[must_use]
    pub fn coalesce(mut self, enabled: bool) -> Self {
        self.coalesce = enabled;
        self
    }

    /// Whether the configuration describes an enabled store.
    pub(crate) fn store_enabled(&self) -> bool {
        self.max_bytes > 0
    }

    /// The configured memory bound.
    pub(crate) fn max_bytes_value(&self) -> usize {
        self.max_bytes
    }

    /// Whether coalescing is enabled.
    pub(crate) fn coalesce_enabled(&self) -> bool {
        self.coalesce
    }

    /// The explicit shard count, if one was set.
    pub(crate) fn shards_value(&self) -> Option<usize> {
        self.shards
    }

    /// The TTL rules.
    pub(crate) fn ttl_policy(&self) -> TtlPolicy {
        TtlPolicy {
            positive: self.positive,
            negative: self.negative,
            negative_without_soa: self.negative_without_soa,
        }
    }
}

/// A point-in-time snapshot of a [`crate::engine::Resolver`]'s cache
/// counters, from [`crate::engine::Resolver::cache_stats`].
///
/// The counters are monotonic over the resolver's lifetime (they are not
/// reset by [`crate::engine::Resolver::clear_cache`]); `entries` and `bytes`
/// describe the current content. The snapshot is read shard by shard without
/// stopping concurrent queries, so under load the values are individually
/// consistent but not an atomic cut across all of them.
///
/// With the store disabled ([`CacheConfig::disabled`]) every figure but
/// `misses` and `coalesced` stays 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
    pub(crate) capacity_bytes: u64,
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) coalesced: u64,
    pub(crate) inserts: u64,
    pub(crate) evictions: u64,
    pub(crate) expirations: u64,
    pub(crate) oversized_rejected: u64,
}

impl CacheStats {
    /// Number of answers currently stored.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Estimated bytes in use: the stored answers plus the remembered hashes
    /// of recently evicted keys. Like [`CacheConfig::max_bytes`], this is a
    /// structural estimate, not an allocator-exact figure.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The configured memory bound as split over the shards (so it can be a
    /// few bytes below [`CacheConfig::max_bytes`]); 0 when the store is
    /// disabled.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    /// Queries answered from the store.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Queries not answered from the store at lookup, including queries that
    /// bypass the cache, and every query when the store is disabled. A
    /// coalesced follower counts here too: it missed, then shared a result.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Queries that joined another query's in-flight upstream call.
    pub fn coalesced(&self) -> u64 {
        self.coalesced
    }

    /// Answers stored. A refreshed key counts again.
    pub fn inserts(&self) -> u64 {
        self.inserts
    }

    /// Entries removed to stay within the memory bound. Expiry, purges and
    /// flushes are not evictions.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Entries removed because their lifetime ended.
    pub fn expirations(&self) -> u64 {
        self.expirations
    }

    /// Answers not stored because one alone was too large for its shard
    /// (more than an eighth of the shard's share of the bound).
    pub fn oversized_rejected(&self) -> u64 {
        self.oversized_rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let config = CacheConfig::default();
        assert_eq!(config.max_bytes_value(), 16 * 1024 * 1024);
        assert!(config.store_enabled());
        assert!(config.coalesce_enabled());
        assert!(!config.clone().coalesce(false).coalesce_enabled());
        assert_eq!(config.shards_value(), None);
        let policy = config.ttl_policy();
        assert_eq!(
            policy.positive,
            TtlBounds {
                min: 0,
                max: 86_400
            }
        );
        assert_eq!(policy.negative, TtlBounds { min: 0, max: 3_600 });
        assert_eq!(policy.negative_without_soa, Some(60));
    }

    #[test]
    fn disabled_and_zero_bytes_turn_the_store_off() {
        assert!(!CacheConfig::disabled().store_enabled());
        assert!(!CacheConfig::new().max_bytes(0).store_enabled());
        assert!(CacheConfig::disabled().max_bytes(1).store_enabled());
    }

    #[test]
    fn ttl_clamps_are_configurable_in_whole_seconds() {
        let config = CacheConfig::new()
            .positive_ttl(Duration::from_millis(5_900), Duration::from_secs(120))
            .negative_ttl(Duration::from_secs(2), Duration::from_secs(30))
            .negative_ttl_without_soa(Some(Duration::from_secs(7)));
        let policy = config.ttl_policy();
        assert_eq!(policy.positive, TtlBounds { min: 5, max: 120 });
        assert_eq!(policy.negative, TtlBounds { min: 2, max: 30 });
        assert_eq!(policy.negative_without_soa, Some(7));
        assert_eq!(policy.positive.clamp(1), 5);
        assert_eq!(policy.positive.clamp(10_000), 120);
        assert_eq!(policy.negative.clamp(10), 10);
        assert_eq!(
            config
                .negative_ttl_without_soa(None)
                .ttl_policy()
                .negative_without_soa,
            None
        );
    }

    #[test]
    fn inverted_and_oversized_bounds_are_normalised() {
        let bounds = TtlBounds::new(Duration::from_secs(50), Duration::from_secs(10));
        assert_eq!(bounds, TtlBounds { min: 50, max: 50 });
        let huge = TtlBounds::new(Duration::ZERO, Duration::from_secs(u64::MAX));
        assert_eq!(huge.max, u32::MAX);
        assert_eq!(huge.clamp(u32::MAX), u32::MAX);
    }

    #[test]
    fn explicit_shard_counts_round_up_to_a_power_of_two_within_limits() {
        for (requested, expected) in [(0, 1), (1, 1), (3, 4), (8, 8), (1000, 1024), (5000, 1024)] {
            assert_eq!(
                CacheConfig::new().shards(requested).shards_value(),
                Some(expected),
                "shards({requested})"
            );
        }
    }
}
