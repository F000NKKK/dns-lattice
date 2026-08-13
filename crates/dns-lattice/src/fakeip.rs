//! Stateful, deterministic Fake IP address allocation.
//!
//! [`FakeIpPool`] maps a DNS [`Name`] to one synthetic address in each
//! configured family. It is a data-only control-plane component: it performs
//! no network I/O, durable persistence, or integration with an external data
//! plane. [`crate::engine::ResolverBuilder::fake_ip`] explicitly combines a
//! pool and [`FakeIpPolicy`] to synthesize local DNS answers. Each mapping has
//! the required pool TTL; expired mappings are removed on pool operations or
//! by an explicit [`FakeIpPool::purge_expired`] call. Callers can retain a
//! [`FakeIpPoolSnapshot`] and restore it into a new pool without this crate
//! serializing it or writing it to storage.
//!
//! Ranges are inclusive. A name's first candidate is selected with a
//! family-salted FNV-1a hash of its canonical (case-insensitive) labels;
//! collisions use circular linear probing. Allocation is deterministic for
//! the current pool state. When all addresses in a family are assigned, the
//! least-recently-used mapping is evicted before a new one is inserted.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{DomainMatcher, DomainPattern, Name};

/// Selects the domain names for which resolver integration synthesizes Fake
/// IP answers.
///
/// This policy only answers whether a name matches. It does not allocate an
/// address or alter DNS messages; [`crate::engine::ResolverBuilder::fake_ip`]
/// combines it with a pool to enable that behavior explicitly.
#[derive(Debug, Clone, Default)]
pub struct FakeIpPolicy {
    matcher: DomainMatcher<()>,
}

impl FakeIpPolicy {
    /// Starts building a policy with no matching rules.
    pub fn builder() -> FakeIpPolicyBuilder {
        FakeIpPolicyBuilder {
            matcher: DomainMatcher::new(),
        }
    }

    /// Returns whether `name` matches the policy under [`DomainMatcher`]'s
    /// documented exact/suffix/wildcard precedence rules.
    pub fn matches(&self, name: &Name) -> bool {
        self.matcher.resolve(name).is_some()
    }
}

/// Builder for [`FakeIpPolicy`].
#[must_use]
pub struct FakeIpPolicyBuilder {
    matcher: DomainMatcher<()>,
}

impl FakeIpPolicyBuilder {
    /// Adds a domain pattern that selects Fake IP behavior.
    pub fn rule(mut self, pattern: DomainPattern) -> Self {
        self.matcher.insert(pattern, ());
        self
    }

    /// Builds the policy. An empty policy matches no names.
    pub fn build(self) -> FakeIpPolicy {
        FakeIpPolicy {
            matcher: self.matcher,
        }
    }
}

/// A concurrent pool of synthetic IPv4 and/or IPv6 addresses keyed by DNS
/// name.
///
/// Construct with [`FakeIpPool::builder`]. Each family has independent
/// forward/reverse mappings and LRU eviction state, so allocating IPv4 never
/// displaces an IPv6 mapping (or vice versa).
pub struct FakeIpPool {
    ipv4: Option<Mutex<FamilyState<u32>>>,
    ipv6: Option<Mutex<FamilyState<u128>>>,
    ttl: Duration,
    clock: Box<dyn Clock + Send + Sync>,
}

/// Caller-owned, in-memory representation of a [`FakeIpPool`].
///
/// `mappings` is ordered deterministically: all IPv4 mappings first and then
/// all IPv6 mappings; within a family the order is least-recently-used to
/// most-recently-used. [`FakeIpPool::restore`] preserves that per-family LRU
/// order. `remaining_lifetime` is sampled when [`FakeIpPool::snapshot`] is
/// called. `captured_at` lets restoration subtract time elapsed while the
/// in-memory snapshot is held, so restoration never extends a mapping's TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIpPoolSnapshot {
    /// Monotonic instant at which `remaining_lifetime` values were sampled.
    ///
    /// This makes a snapshot process-local in-memory data: it is not a
    /// serialization format and is not meaningful across process restarts.
    pub captured_at: Instant,
    /// The inclusive IPv4 allocation range, if IPv4 is configured.
    pub ipv4_range: Option<(Ipv4Addr, Ipv4Addr)>,
    /// The inclusive IPv6 allocation range, if IPv6 is configured.
    pub ipv6_range: Option<(Ipv6Addr, Ipv6Addr)>,
    /// The required lifetime configured for new mappings.
    pub ttl: Duration,
    /// Live mappings in deterministic per-family LRU order.
    pub mappings: Vec<FakeIpMappingSnapshot>,
}

/// One live mapping stored in a [`FakeIpPoolSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIpMappingSnapshot {
    /// The canonical DNS name associated with this synthetic address.
    pub name: Name,
    /// The synthetic IPv4 or IPv6 address.
    pub address: IpAddr,
    /// Lifetime still remaining at the moment the snapshot was taken.
    pub remaining_lifetime: Duration,
}

impl FakeIpPool {
    /// Starts building a Fake IP pool with no configured address families.
    pub fn builder() -> FakeIpPoolBuilder {
        FakeIpPoolBuilder {
            ipv4: None,
            ipv6: None,
            ttl: None,
            clock: Box::new(SystemClock),
        }
    }

    /// Returns the lifetime assigned to each mapping.
    ///
    /// Resolver integrations use a mapping's remaining portion of this value
    /// as the TTL of synthetic DNS records, so a client-facing answer cannot
    /// outlive its mapping.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns whether this pool has an IPv4 allocation range.
    ///
    /// Crate-private resolver orchestration uses this before validating a
    /// wire TTL so a selected but disabled family can return local NODATA
    /// without an allocation or an unrelated TTL error.
    pub(crate) fn ipv4_enabled(&self) -> bool {
        self.ipv4.is_some()
    }

    /// Returns whether this pool has an IPv6 allocation range.
    ///
    /// Crate-private resolver orchestration uses this before validating a
    /// wire TTL so a selected but disabled family can return local NODATA
    /// without an allocation or an unrelated TTL error.
    pub(crate) fn ipv6_enabled(&self) -> bool {
        self.ipv6.is_some()
    }

    /// Captures the pool's configured ranges, TTL, and currently live
    /// mappings.
    ///
    /// The returned value is caller-owned in-memory data. It performs no
    /// serialization or I/O. Expired mappings are omitted, and this call does
    /// not refresh any mapping's LRU recency.
    pub fn snapshot(&self) -> FakeIpPoolSnapshot {
        let now = self.clock.now();
        let mut mappings = Vec::new();
        let ipv4_range = self.ipv4.as_ref().map(|state| {
            let mut state = state.lock().expect("fake ip ipv4 mutex poisoned");
            state.purge_expired(now);
            mappings.extend(state.snapshot(now, |address| IpAddr::V4(Ipv4Addr::from(address))));
            (Ipv4Addr::from(state.start), Ipv4Addr::from(state.end))
        });
        let ipv6_range = self.ipv6.as_ref().map(|state| {
            let mut state = state.lock().expect("fake ip ipv6 mutex poisoned");
            state.purge_expired(now);
            mappings.extend(state.snapshot(now, |address| IpAddr::V6(Ipv6Addr::from(address))));
            (Ipv6Addr::from(state.start), Ipv6Addr::from(state.end))
        });
        FakeIpPoolSnapshot {
            captured_at: now,
            ipv4_range,
            ipv6_range,
            ttl: self.ttl,
            mappings,
        }
    }

    /// Restores a new pool from a caller-owned [`FakeIpPoolSnapshot`].
    ///
    /// Restoration validates every range, TTL, mapping address, and duplicate
    /// name/address before returning a pool. A mapping with no remaining
    /// lifetime after the time held since `captured_at` is omitted. Any other
    /// invalid snapshot returns
    /// [`Error::InvalidFakeIpSnapshot`] without producing a partially restored
    /// pool.
    pub fn restore(snapshot: FakeIpPoolSnapshot) -> Result<Self> {
        Self::restore_with_clock(snapshot, Box::new(SystemClock))
    }

    #[cfg(test)]
    fn restore_with_test_clock(
        snapshot: FakeIpPoolSnapshot,
        clock: impl Clock + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::restore_with_clock(snapshot, Box::new(clock))
    }

    fn restore_with_clock(
        snapshot: FakeIpPoolSnapshot,
        clock: Box<dyn Clock + Send + Sync>,
    ) -> Result<Self> {
        validate_ttl(snapshot.ttl).map_err(|_| Error::InvalidFakeIpSnapshot)?;
        let now = clock.now();
        let elapsed = now
            .checked_duration_since(snapshot.captured_at)
            .ok_or(Error::InvalidFakeIpSnapshot)?;
        let mut ipv4 = snapshot
            .ipv4_range
            .map(|(start, end)| FamilyState::new((u32::from(start), u32::from(end))))
            .transpose()
            .map_err(|_| Error::InvalidFakeIpSnapshot)?;
        let mut ipv6 = snapshot
            .ipv6_range
            .map(|(start, end)| FamilyState::new((u128::from(start), u128::from(end))))
            .transpose()
            .map_err(|_| Error::InvalidFakeIpSnapshot)?;
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::InvalidFakeIpSnapshot);
        }

        for mapping in snapshot.mappings {
            if mapping.remaining_lifetime > snapshot.ttl {
                return Err(Error::InvalidFakeIpSnapshot);
            }
            let Some(remaining_lifetime) = mapping.remaining_lifetime.checked_sub(elapsed) else {
                continue;
            };
            if remaining_lifetime.is_zero() {
                continue;
            }
            let expires_at = now
                .checked_add(remaining_lifetime)
                .ok_or(Error::InvalidFakeIpSnapshot)?;
            match mapping.address {
                IpAddr::V4(address) => ipv4
                    .as_mut()
                    .filter(|state| state.contains(u32::from(address)))
                    .ok_or(Error::InvalidFakeIpSnapshot)?
                    .restore(mapping.name, u32::from(address), expires_at)?,
                IpAddr::V6(address) => ipv6
                    .as_mut()
                    .filter(|state| state.contains(u128::from(address)))
                    .ok_or(Error::InvalidFakeIpSnapshot)?
                    .restore(mapping.name, u128::from(address), expires_at)?,
            }
        }

        Ok(Self {
            ipv4: ipv4.map(Mutex::new),
            ipv6: ipv6.map(Mutex::new),
            ttl: snapshot.ttl,
            clock,
        })
    }

    /// Allocates or reuses this name's synthetic IPv4 address.
    ///
    /// Returns [`Error::FakeIpFamilyDisabled`] if no IPv4 range was
    /// configured. Reusing an existing mapping refreshes its LRU recency.
    pub fn allocate_ipv4(&self, name: Name) -> Result<Ipv4Addr> {
        self.allocate_ipv4_with_ttl(name)
            .map(|(address, _)| address)
    }

    /// Allocates or reuses this name's synthetic IPv4 address and returns its
    /// remaining mapping lifetime atomically with the address.
    ///
    /// Reuse changes only LRU recency; it never extends the mapping expiry.
    /// The lifetime can be used as a DNS record TTL without allowing the
    /// record to outlive the mapping.
    pub fn allocate_ipv4_with_ttl(&self, name: Name) -> Result<(Ipv4Addr, Duration)> {
        let state = self.ipv4.as_ref().ok_or(Error::FakeIpFamilyDisabled)?;
        let mut state = state.lock().expect("fake ip ipv4 mutex poisoned");
        let now = self.clock.now();
        let (address, ttl) = state.allocate_with_ttl(name, IPV4_HASH_SALT, now, self.ttl)?;
        Ok((Ipv4Addr::from(address), ttl))
    }

    /// Allocates or reuses this name's synthetic IPv6 address.
    ///
    /// Returns [`Error::FakeIpFamilyDisabled`] if no IPv6 range was
    /// configured. Reusing an existing mapping refreshes its LRU recency.
    pub fn allocate_ipv6(&self, name: Name) -> Result<Ipv6Addr> {
        self.allocate_ipv6_with_ttl(name)
            .map(|(address, _)| address)
    }

    /// Allocates or reuses this name's synthetic IPv6 address and returns its
    /// remaining mapping lifetime atomically with the address.
    ///
    /// Reuse changes only LRU recency; it never extends the mapping expiry.
    /// The lifetime can be used as a DNS record TTL without allowing the
    /// record to outlive the mapping.
    pub fn allocate_ipv6_with_ttl(&self, name: Name) -> Result<(Ipv6Addr, Duration)> {
        let state = self.ipv6.as_ref().ok_or(Error::FakeIpFamilyDisabled)?;
        let mut state = state.lock().expect("fake ip ipv6 mutex poisoned");
        let now = self.clock.now();
        let (address, ttl) = state.allocate_with_ttl(name, IPV6_HASH_SALT, now, self.ttl)?;
        Ok((Ipv6Addr::from(address), ttl))
    }

    /// Returns the name currently mapped to `address` in the IPv4 pool.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// the mapping's LRU recency.
    pub fn lookup_ipv4(&self, address: Ipv4Addr) -> Option<Name> {
        self.lookup_ipv4_with_ttl(address).map(|(name, _)| name)
    }

    /// Returns the name and remaining mapping lifetime for `address` in the
    /// IPv4 pool atomically.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// only LRU recency, never mapping expiry.
    pub fn lookup_ipv4_with_ttl(&self, address: Ipv4Addr) -> Option<(Name, Duration)> {
        let mut state = self
            .ipv4
            .as_ref()?
            .lock()
            .expect("fake ip ipv4 mutex poisoned");
        let now = self.clock.now();
        state.lookup_with_ttl(u32::from(address), now)
    }

    /// Returns the name currently mapped to `address` in the IPv6 pool.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// the mapping's LRU recency.
    pub fn lookup_ipv6(&self, address: Ipv6Addr) -> Option<Name> {
        self.lookup_ipv6_with_ttl(address).map(|(name, _)| name)
    }

    /// Returns the name and remaining mapping lifetime for `address` in the
    /// IPv6 pool atomically.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// only LRU recency, never mapping expiry.
    pub fn lookup_ipv6_with_ttl(&self, address: Ipv6Addr) -> Option<(Name, Duration)> {
        let mut state = self
            .ipv6
            .as_ref()?
            .lock()
            .expect("fake ip ipv6 mutex poisoned");
        let now = self.clock.now();
        state.lookup_with_ttl(u128::from(address), now)
    }

    /// Returns whether `address` lies in this pool's configured IPv4 range.
    /// A disabled IPv4 family returns `false`.
    pub fn contains_ipv4(&self, address: Ipv4Addr) -> bool {
        self.ipv4.as_ref().is_some_and(|state| {
            state
                .lock()
                .expect("fake ip ipv4 mutex poisoned")
                .contains(u32::from(address))
        })
    }

    /// Returns whether `address` lies in this pool's configured IPv6 range.
    /// A disabled IPv6 family returns `false`.
    pub fn contains_ipv6(&self, address: Ipv6Addr) -> bool {
        self.ipv6.as_ref().is_some_and(|state| {
            state
                .lock()
                .expect("fake ip ipv6 mutex poisoned")
                .contains(u128::from(address))
        })
    }

    /// Removes every mapping whose TTL has expired and returns the number
    /// removed. Allocation and reverse lookup also perform this cleanup.
    pub fn purge_expired(&self) -> usize {
        let now = self.clock.now();
        let ipv4 = self.ipv4.as_ref().map_or(0, |state| {
            state
                .lock()
                .expect("fake ip ipv4 mutex poisoned")
                .purge_expired(now)
        });
        let ipv6 = self.ipv6.as_ref().map_or(0, |state| {
            state
                .lock()
                .expect("fake ip ipv6 mutex poisoned")
                .purge_expired(now)
        });
        ipv4 + ipv6
    }
}

/// Builder for [`FakeIpPool`].
#[must_use]
pub struct FakeIpPoolBuilder {
    ipv4: Option<(u32, u32)>,
    ipv6: Option<(u128, u128)>,
    ttl: Option<Duration>,
    clock: Box<dyn Clock + Send + Sync>,
}

impl FakeIpPoolBuilder {
    /// Configures the inclusive IPv4 allocation range, replacing any prior
    /// IPv4 range on this builder.
    pub fn ipv4_range(mut self, start: Ipv4Addr, end: Ipv4Addr) -> Self {
        self.ipv4 = Some((u32::from(start), u32::from(end)));
        self
    }

    /// Configures the inclusive IPv6 allocation range, replacing any prior
    /// IPv6 range on this builder.
    pub fn ipv6_range(mut self, start: Ipv6Addr, end: Ipv6Addr) -> Self {
        self.ipv6 = Some((u128::from(start), u128::from(end)));
        self
    }

    /// Sets the lifetime of every allocation. It must be a non-zero whole
    /// number of seconds. Resolver synthesis advertises no more than the
    /// mapping's remaining lifetime in a DNS answer.
    ///
    /// This is required as of the pre-1.0 0.4 API revision; callers of the
    /// earlier pool-only API must explicitly choose their desired lifetime.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Clock + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Validates the configured ranges and builds the pool.
    ///
    /// At least one address family must be configured. An invalid inclusive
    /// range returns [`Error::InvalidFakeIpRange`].
    pub fn build(self) -> Result<FakeIpPool> {
        let ttl = self.ttl.ok_or(Error::InvalidFakeIpTtl)?;
        validate_ttl(ttl)?;
        let ipv4 = self.ipv4.map(FamilyState::new).transpose()?;
        let ipv6 = self.ipv6.map(FamilyState::new).transpose()?;
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::FakeIpPoolUnconfigured);
        }
        Ok(FakeIpPool {
            ipv4: ipv4.map(Mutex::new),
            ipv6: ipv6.map(Mutex::new),
            ttl,
            clock: self.clock,
        })
    }
}

struct FamilyState<T> {
    start: T,
    end: T,
    forward: HashMap<Name, Mapping<T>>,
    reverse: HashMap<T, Name>,
    next_recency: u64,
    next_allocation: u64,
}

struct Mapping<T> {
    address: T,
    recency: u64,
    allocation: u64,
    expires_at: Instant,
}

pub(crate) trait Clock {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait Address: Copy + Eq + Ord + std::hash::Hash {
    /// `None` represents the whole address space, whose cardinality does
    /// not fit in the address type.
    fn capacity(start: Self, end: Self) -> Option<Self>;
    fn candidate(start: Self, end: Self, hash: u64) -> Self;
    fn advance(value: Self) -> Self;
    fn is_full(entries: usize, capacity: Self) -> bool;
}

impl Address for u32 {
    fn capacity(start: Self, end: Self) -> Option<Self> {
        end.checked_sub(start)?.checked_add(1)
    }
    fn candidate(start: Self, end: Self, hash: u64) -> Self {
        let length = u64::from(end) - u64::from(start) + 1;
        start + (hash % length) as u32
    }
    fn advance(value: Self) -> Self {
        value.wrapping_add(1)
    }
    fn is_full(entries: usize, capacity: Self) -> bool {
        entries as u64 >= u64::from(capacity)
    }
}

impl Address for u128 {
    fn capacity(start: Self, end: Self) -> Option<Self> {
        end.checked_sub(start)?.checked_add(1)
    }
    fn candidate(start: Self, end: Self, hash: u64) -> Self {
        match end
            .checked_sub(start)
            .and_then(|distance| distance.checked_add(1))
        {
            Some(length) => start + (u128::from(hash) % length),
            None => start.wrapping_add(u128::from(hash)),
        }
    }
    fn advance(value: Self) -> Self {
        value.wrapping_add(1)
    }
    fn is_full(entries: usize, capacity: Self) -> bool {
        entries as u128 >= capacity
    }
}

impl<T: Address> FamilyState<T> {
    fn new((start, end): (T, T)) -> Result<Self> {
        if start > end {
            return Err(Error::InvalidFakeIpRange);
        }
        Ok(Self {
            start,
            end,
            forward: HashMap::new(),
            reverse: HashMap::new(),
            next_recency: 0,
            next_allocation: 0,
        })
    }

    fn allocate_with_ttl(
        &mut self,
        name: Name,
        salt: u64,
        now: Instant,
        ttl: Duration,
    ) -> Result<(T, Duration)> {
        let expires_at = now.checked_add(ttl).ok_or(Error::FakeIpTtlOutOfRange)?;
        self.purge_expired(now);
        if self.forward.contains_key(&name) {
            let recency = self.touch();
            let mapping = self.forward.get_mut(&name).expect("mapping checked above");
            mapping.recency = recency;
            return Ok((
                mapping.address,
                mapping
                    .expires_at
                    .checked_duration_since(now)
                    .expect("expired mappings were purged"),
            ));
        }
        if self
            .capacity()
            .is_some_and(|capacity| T::is_full(self.forward.len(), capacity))
        {
            self.evict_lru();
        }
        let mut address = self.candidate(fnv1a(&name, salt));
        while self.reverse.contains_key(&address) {
            address = if address == self.end {
                self.start
            } else {
                T::advance(address)
            };
        }
        let recency = self.touch();
        let allocation = self.next_allocation;
        self.next_allocation = self.next_allocation.wrapping_add(1);
        self.reverse.insert(address, name.clone());
        self.forward.insert(
            name,
            Mapping {
                address,
                recency,
                allocation,
                expires_at,
            },
        );
        Ok((address, ttl))
    }

    fn lookup_with_ttl(&mut self, address: T, now: Instant) -> Option<(Name, Duration)> {
        self.purge_expired(now);
        if !self.contains(address) {
            return None;
        }
        let name = self.reverse.get(&address)?.clone();
        let recency = self.touch();
        let mapping = self.forward.get_mut(&name)?;
        mapping.recency = recency;
        Some((
            name,
            mapping
                .expires_at
                .checked_duration_since(now)
                .expect("expired mappings were purged"),
        ))
    }

    fn candidate(&self, hash: u64) -> T {
        T::candidate(self.start, self.end, hash)
    }

    fn contains(&self, address: T) -> bool {
        address >= self.start && address <= self.end
    }

    fn purge_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<_> = self
            .forward
            .iter()
            .filter(|(_, mapping)| mapping.expires_at <= now)
            .map(|(name, _)| name.clone())
            .collect();
        for name in &expired {
            let mapping = self.forward.remove(name).expect("mapping selected above");
            self.reverse.remove(&mapping.address);
        }
        expired.len()
    }

    fn snapshot<A>(&self, now: Instant, address: impl Fn(T) -> A) -> Vec<FakeIpMappingSnapshot>
    where
        A: Into<IpAddr>,
    {
        let mut mappings: Vec<_> = self.forward.iter().collect();
        mappings.sort_by_key(|(_, mapping)| (mapping.recency, mapping.allocation));
        mappings
            .into_iter()
            .filter_map(|(name, mapping)| {
                mapping
                    .expires_at
                    .checked_duration_since(now)
                    .map(|remaining_lifetime| FakeIpMappingSnapshot {
                        name: name.clone(),
                        address: address(mapping.address).into(),
                        remaining_lifetime,
                    })
            })
            .collect()
    }

    fn restore(&mut self, name: Name, address: T, expires_at: Instant) -> Result<()> {
        if self.forward.contains_key(&name) || self.reverse.contains_key(&address) {
            return Err(Error::InvalidFakeIpSnapshot);
        }
        let recency = self.touch();
        let allocation = self.next_allocation;
        self.next_allocation = self.next_allocation.wrapping_add(1);
        self.reverse.insert(address, name.clone());
        self.forward.insert(
            name,
            Mapping {
                address,
                recency,
                allocation,
                expires_at,
            },
        );
        Ok(())
    }

    fn capacity(&self) -> Option<T> {
        T::capacity(self.start, self.end)
    }

    fn evict_lru(&mut self) {
        let name = self
            .forward
            .iter()
            .min_by_key(|(_, mapping)| (mapping.recency, mapping.allocation))
            .map(|(name, _)| name.clone())
            .expect("full fake ip pool has a mapping");
        let mapping = self.forward.remove(&name).expect("mapping selected above");
        self.reverse.remove(&mapping.address);
    }

    fn touch(&mut self) -> u64 {
        let recency = self.next_recency;
        self.next_recency = self.next_recency.wrapping_add(1);
        recency
    }
}

fn validate_ttl(ttl: Duration) -> Result<()> {
    if ttl.is_zero() || ttl.subsec_nanos() != 0 {
        return Err(Error::InvalidFakeIpTtl);
    }
    Ok(())
}

const IPV4_HASH_SALT: u64 = 0x9B73_9F4A_A5C3_17D1;
const IPV6_HASH_SALT: u64 = 0xE1D4_62B8_3F90_AC75;

fn fnv1a(name: &Name, salt: u64) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ salt;
    for label in name.labels() {
        for byte in label {
            hash ^= u64::from(byte.to_ascii_lowercase());
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
        hash ^= 0;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn name(value: &str) -> Name {
        Name::from_ascii(value).unwrap()
    }

    fn pool_builder() -> FakeIpPoolBuilder {
        FakeIpPool::builder().ttl(Duration::from_secs(30))
    }

    #[derive(Clone)]
    struct FakeClock(Arc<Mutex<Instant>>);

    impl FakeClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.0.lock().expect("fake clock mutex poisoned");
            *now += duration;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().expect("fake clock mutex poisoned")
        }
    }

    #[test]
    fn policy_uses_domain_matcher_precedence_case_insensitively() {
        let policy = FakeIpPolicy::builder()
            .rule(DomainPattern::wildcard(name("example.test")))
            .rule(DomainPattern::suffix(name("example.test")))
            .rule(DomainPattern::exact(name("api.example.test")))
            .build();

        assert!(policy.matches(&name("API.EXAMPLE.TEST")));
        assert!(policy.matches(&name("worker.example.test")));
        assert!(!policy.matches(&name("example.invalid")));
        assert!(
            !FakeIpPolicy::builder()
                .build()
                .matches(&name("example.test"))
        );
    }

    #[test]
    fn pool_exposes_the_mapping_ttl_for_synthetic_dns_answers() {
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(42))
            .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
            .build()
            .unwrap();
        assert_eq!(pool.ttl(), Duration::from_secs(42));
    }

    #[test]
    fn validates_configuration_and_disabled_families() {
        assert!(matches!(
            FakeIpPool::builder().build(),
            Err(Error::InvalidFakeIpTtl)
        ));
        assert!(matches!(
            pool_builder()
                .ipv4_range(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1))
                .build(),
            Err(Error::InvalidFakeIpRange)
        ));

        let pool = pool_builder()
            .ipv4_range(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .build()
            .unwrap();
        assert_eq!(
            pool.allocate_ipv6(name("example.test")).unwrap_err(),
            Error::FakeIpFamilyDisabled
        );
        assert_eq!(pool.lookup_ipv6(Ipv6Addr::LOCALHOST), None);

        assert!(matches!(
            FakeIpPool::builder()
                .ttl(Duration::ZERO)
                .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
                .build(),
            Err(Error::InvalidFakeIpTtl)
        ));
        assert!(matches!(
            FakeIpPool::builder()
                .ttl(Duration::from_millis(1))
                .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
                .build(),
            Err(Error::InvalidFakeIpTtl)
        ));
    }

    #[test]
    fn unrepresentable_whole_second_ttl_returns_a_typed_error_without_panicking() {
        let clock = FakeClock::new();
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(u64::MAX))
            .clock(clock)
            .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
            .build()
            .unwrap();

        assert_eq!(
            pool.allocate_ipv4(name("overflow.test")),
            Err(Error::FakeIpTtlOutOfRange)
        );

        assert!(matches!(
            FakeIpPool::builder()
                .ttl(Duration::MAX)
                .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
                .build(),
            Err(Error::InvalidFakeIpTtl)
        ));
    }

    #[test]
    fn expiry_is_exact_and_removes_forward_and_reverse_mappings() {
        let clock = FakeClock::new();
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(5))
            .clock(clock.clone())
            .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
            .build()
            .unwrap();
        let address = pool.allocate_ipv4(name("expired.test")).unwrap();

        clock.advance(Duration::from_secs(4));
        assert_eq!(pool.lookup_ipv4(address), Some(name("expired.test")));
        clock.advance(Duration::from_secs(1));
        assert_eq!(pool.lookup_ipv4(address), None);
        assert_eq!(pool.purge_expired(), 0);
        assert_eq!(pool.allocate_ipv4(name("expired.test")).unwrap(), address);
    }

    #[test]
    fn explicit_purge_frees_capacity_before_lru_eviction() {
        let clock = FakeClock::new();
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(2))
            .clock(clock.clone())
            .ipv4_range(Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2))
            .build()
            .unwrap();
        let expired = pool.allocate_ipv4(name("expired.test")).unwrap();
        clock.advance(Duration::from_secs(1));
        let live = pool.allocate_ipv4(name("live.test")).unwrap();

        clock.advance(Duration::from_secs(1));
        assert_eq!(pool.purge_expired(), 1);
        assert_eq!(pool.lookup_ipv4(expired), None);
        assert_eq!(pool.lookup_ipv4(live), Some(name("live.test")));
        let fresh = pool.allocate_ipv4(name("fresh.test")).unwrap();
        assert!(pool.contains_ipv4(fresh));
        assert_eq!(pool.lookup_ipv4(live), Some(name("live.test")));
        assert!(!pool.contains_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!pool.contains_ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn snapshot_restore_preserves_live_mappings_ttl_and_lru_order() {
        let clock = FakeClock::new();
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(10))
            .clock(clock.clone())
            .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))
            .build()
            .unwrap();
        let alpha = name("alpha.snapshot.test");
        let bravo = name("bravo.snapshot.test");
        let charlie = name("charlie.snapshot.test");
        let alpha_address = pool.allocate_ipv4(alpha.clone()).unwrap();
        let bravo_address = pool.allocate_ipv4(bravo.clone()).unwrap();
        assert_eq!(pool.lookup_ipv4(alpha_address), Some(alpha.clone()));
        clock.advance(Duration::from_secs(1));

        let snapshot = pool.snapshot();
        assert_eq!(snapshot.ttl, Duration::from_secs(10));
        assert_eq!(snapshot.mappings.len(), 2);
        assert_eq!(snapshot.mappings[0].name, bravo);
        assert_eq!(snapshot.mappings[1].name, alpha);
        assert!(
            snapshot
                .mappings
                .iter()
                .all(|mapping| mapping.remaining_lifetime == Duration::from_secs(9))
        );

        clock.advance(Duration::from_secs(4));
        let restored = FakeIpPool::restore_with_test_clock(snapshot, clock.clone()).unwrap();
        let charlie_address = restored.allocate_ipv4(charlie.clone()).unwrap();
        assert_eq!(restored.lookup_ipv4(bravo_address), Some(charlie));
        assert_eq!(charlie_address, bravo_address);
        assert_eq!(restored.lookup_ipv4(alpha_address), Some(alpha));
        clock.advance(Duration::from_secs(5));
        assert_eq!(restored.lookup_ipv4(alpha_address), None);
    }

    #[test]
    fn snapshot_omits_expired_mappings_and_restore_skips_zero_lifetime_entries() {
        let clock = FakeClock::new();
        let pool = FakeIpPool::builder()
            .ttl(Duration::from_secs(2))
            .clock(clock.clone())
            .ipv4_range(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)
            .build()
            .unwrap();
        pool.allocate_ipv4(name("expired.snapshot.test")).unwrap();
        let held_snapshot = pool.snapshot();
        clock.advance(Duration::from_secs(2));
        assert!(pool.snapshot().mappings.is_empty());
        let restored_held =
            FakeIpPool::restore_with_test_clock(held_snapshot, clock.clone()).unwrap();
        assert_eq!(restored_held.lookup_ipv4(Ipv4Addr::LOCALHOST), None);

        let snapshot = FakeIpPoolSnapshot {
            captured_at: clock.now(),
            ipv4_range: Some((Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST)),
            ipv6_range: None,
            ttl: Duration::from_secs(2),
            mappings: vec![FakeIpMappingSnapshot {
                name: name("zero.snapshot.test"),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                remaining_lifetime: Duration::ZERO,
            }],
        };
        let restored = FakeIpPool::restore_with_test_clock(snapshot, clock).unwrap();
        assert_eq!(restored.lookup_ipv4(Ipv4Addr::LOCALHOST), None);
    }

    #[test]
    fn restore_rejects_invalid_ranges_ttls_addresses_and_duplicates() {
        let valid_mapping = FakeIpMappingSnapshot {
            name: name("valid.snapshot.test"),
            address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            remaining_lifetime: Duration::from_secs(1),
        };
        let base = FakeIpPoolSnapshot {
            captured_at: Instant::now(),
            ipv4_range: Some((Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 2))),
            ipv6_range: None,
            ttl: Duration::from_secs(2),
            mappings: vec![valid_mapping.clone()],
        };
        let invalid = [
            FakeIpPoolSnapshot {
                ipv4_range: None,
                ipv6_range: None,
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                ttl: Duration::ZERO,
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                ipv4_range: Some((Ipv4Addr::new(198, 18, 0, 2), Ipv4Addr::new(198, 18, 0, 1))),
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                mappings: vec![FakeIpMappingSnapshot {
                    address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ..valid_mapping.clone()
                }],
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                mappings: vec![FakeIpMappingSnapshot {
                    address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 9)),
                    ..valid_mapping.clone()
                }],
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                mappings: vec![valid_mapping.clone(), valid_mapping.clone()],
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                mappings: vec![
                    valid_mapping.clone(),
                    FakeIpMappingSnapshot {
                        name: name("second.snapshot.test"),
                        ..valid_mapping.clone()
                    },
                ],
                ..base.clone()
            },
            FakeIpPoolSnapshot {
                mappings: vec![FakeIpMappingSnapshot {
                    remaining_lifetime: Duration::from_secs(3),
                    ..valid_mapping
                }],
                ..base
            },
        ];
        for snapshot in invalid {
            assert!(matches!(
                FakeIpPool::restore(snapshot),
                Err(Error::InvalidFakeIpSnapshot)
            ));
        }
    }

    #[test]
    fn allocation_is_case_insensitive_reusable_and_reversible() {
        let pool = pool_builder()
            .ipv4_range(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 16))
            .ipv6_range("fd00::1".parse().unwrap(), "fd00::10".parse().unwrap())
            .build()
            .unwrap();
        let ipv4 = pool.allocate_ipv4(name("Example.Test.")).unwrap();
        let ipv6 = pool.allocate_ipv6(name("Example.Test.")).unwrap();

        assert_eq!(pool.allocate_ipv4(name("example.test")).unwrap(), ipv4);
        assert_eq!(pool.allocate_ipv6(name("EXAMPLE.TEST")).unwrap(), ipv6);
        assert_eq!(pool.lookup_ipv4(ipv4), Some(name("Example.Test")));
        assert_eq!(pool.lookup_ipv6(ipv6), Some(name("Example.Test")));
        assert_eq!(pool.lookup_ipv4(Ipv4Addr::new(192, 0, 2, 1)), None);
    }

    #[test]
    fn allocation_is_deterministic_for_the_same_pool_state() {
        let make_pool = || {
            pool_builder()
                .ipv4_range(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 16))
                .build()
                .unwrap()
        };
        let first = make_pool();
        let second = make_pool();
        for domain in ["one.test", "two.test", "three.test"] {
            assert_eq!(
                first.allocate_ipv4(name(domain)).unwrap(),
                second.allocate_ipv4(name(domain)).unwrap()
            );
        }
    }

    #[test]
    fn known_hash_collision_uses_circular_probe_with_inclusive_bounds() {
        let start = Ipv4Addr::new(198, 18, 0, 10);
        let end = Ipv4Addr::new(198, 18, 0, 12);
        let pool = pool_builder().ipv4_range(start, end).build().unwrap();

        // Both canonical names have an IPv4-salted FNV-1a hash that maps to
        // the inclusive range's final address (their hashes end in `54` and
        // `2c`, respectively). The second allocation must therefore probe
        // across the inclusive boundary to `start`, rather than replacing
        // the first mapping.
        assert_eq!(fnv1a(&name("alpha.test"), IPV4_HASH_SALT) % 3, 2);
        assert_eq!(fnv1a(&name("bravo.test"), IPV4_HASH_SALT) % 3, 2);
        assert_eq!(pool.allocate_ipv4(name("alpha.test")).unwrap(), end);
        assert_eq!(pool.allocate_ipv4(name("bravo.test")).unwrap(), start);
        assert_eq!(pool.lookup_ipv4(Ipv4Addr::new(198, 18, 0, 11)), None);

        let singleton = pool_builder()
            .ipv6_range("fd00::42".parse().unwrap(), "fd00::42".parse().unwrap())
            .build()
            .unwrap();
        assert_eq!(
            singleton.allocate_ipv6(name("singleton.test")).unwrap(),
            "fd00::42".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn concurrent_allocations_reuse_and_reverse_lookup_in_each_family() {
        let pool = Arc::new(
            pool_builder()
                .ipv4_range(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 64))
                .ipv6_range("fd00::1".parse().unwrap(), "fd00::40".parse().unwrap())
                .build()
                .unwrap(),
        );
        let mut handles = Vec::new();
        for index in 0..32 {
            let pool = Arc::clone(&pool);
            handles.push(std::thread::spawn(move || {
                let domain = format!("member-{index}.test");
                let upper = domain.to_ascii_uppercase();
                let ipv4 = pool.allocate_ipv4(name(&domain)).unwrap();
                let ipv6 = pool.allocate_ipv6(name(&domain)).unwrap();
                assert_eq!(pool.allocate_ipv4(name(&upper)).unwrap(), ipv4);
                assert_eq!(pool.allocate_ipv6(name(&upper)).unwrap(), ipv6);
                assert_eq!(pool.lookup_ipv4(ipv4), Some(name(&domain)));
                assert_eq!(pool.lookup_ipv6(ipv6), Some(name(&domain)));
                (domain, ipv4, ipv6)
            }));
        }

        let mappings: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let ipv4_addresses: HashSet<_> = mappings.iter().map(|(_, ipv4, _)| *ipv4).collect();
        let ipv6_addresses: HashSet<_> = mappings.iter().map(|(_, _, ipv6)| *ipv6).collect();
        assert_eq!(ipv4_addresses.len(), mappings.len());
        assert_eq!(ipv6_addresses.len(), mappings.len());
        for (domain, ipv4, ipv6) in mappings {
            assert_eq!(pool.lookup_ipv4(ipv4), Some(name(&domain)));
            assert_eq!(pool.lookup_ipv6(ipv6), Some(name(&domain)));
        }
    }

    #[test]
    fn full_family_evicts_the_least_recently_used_mapping() {
        let pool = pool_builder()
            .ipv4_range(Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2))
            .build()
            .unwrap();
        let first = pool.allocate_ipv4(name("first.test")).unwrap();
        let second = pool.allocate_ipv4(name("second.test")).unwrap();
        assert_eq!(pool.lookup_ipv4(first), Some(name("first.test")));

        let third = pool.allocate_ipv4(name("third.test")).unwrap();
        assert!(third == first || third == second);
        assert_ne!(pool.lookup_ipv4(second), Some(name("second.test")));
        assert_eq!(pool.lookup_ipv4(first), Some(name("first.test")));
        assert_eq!(pool.lookup_ipv4(third), Some(name("third.test")));
    }
}
