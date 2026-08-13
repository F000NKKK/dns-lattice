//! Stateful, deterministic Fake IP address allocation.
//!
//! [`FakeIpPool`] maps a DNS [`Name`] to one synthetic address in each
//! configured family. It is a data-only control-plane component: it neither
//! rewrites DNS messages nor performs PTR synthesis, TTL handling, network
//! I/O, persistence, or tunnel integration.
//!
//! Ranges are inclusive. A name's first candidate is selected with a
//! family-salted FNV-1a hash of its canonical (case-insensitive) labels;
//! collisions use circular linear probing. Allocation is deterministic for
//! the current pool state. When all addresses in a family are assigned, the
//! least-recently-used mapping is evicted before a new one is inserted.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use dns_lattice_core::{Error, Result};
use dns_lattice_model::Name;

/// A concurrent pool of synthetic IPv4 and/or IPv6 addresses keyed by DNS
/// name.
///
/// Construct with [`FakeIpPool::builder`]. Each family has independent
/// forward/reverse mappings and LRU eviction state, so allocating IPv4 never
/// displaces an IPv6 mapping (or vice versa).
pub struct FakeIpPool {
    ipv4: Option<Mutex<FamilyState<u32>>>,
    ipv6: Option<Mutex<FamilyState<u128>>>,
}

impl FakeIpPool {
    /// Starts building a Fake IP pool with no configured address families.
    pub fn builder() -> FakeIpPoolBuilder {
        FakeIpPoolBuilder {
            ipv4: None,
            ipv6: None,
        }
    }

    /// Allocates or reuses this name's synthetic IPv4 address.
    ///
    /// Returns [`Error::FakeIpFamilyDisabled`] if no IPv4 range was
    /// configured. Reusing an existing mapping refreshes its LRU recency.
    pub fn allocate_ipv4(&self, name: Name) -> Result<Ipv4Addr> {
        let state = self.ipv4.as_ref().ok_or(Error::FakeIpFamilyDisabled)?;
        Ok(Ipv4Addr::from(
            state
                .lock()
                .expect("fake ip ipv4 mutex poisoned")
                .allocate(name, IPV4_HASH_SALT),
        ))
    }

    /// Allocates or reuses this name's synthetic IPv6 address.
    ///
    /// Returns [`Error::FakeIpFamilyDisabled`] if no IPv6 range was
    /// configured. Reusing an existing mapping refreshes its LRU recency.
    pub fn allocate_ipv6(&self, name: Name) -> Result<Ipv6Addr> {
        let state = self.ipv6.as_ref().ok_or(Error::FakeIpFamilyDisabled)?;
        Ok(Ipv6Addr::from(
            state
                .lock()
                .expect("fake ip ipv6 mutex poisoned")
                .allocate(name, IPV6_HASH_SALT),
        ))
    }

    /// Returns the name currently mapped to `address` in the IPv4 pool.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// the mapping's LRU recency.
    pub fn lookup_ipv4(&self, address: Ipv4Addr) -> Option<Name> {
        self.ipv4
            .as_ref()?
            .lock()
            .expect("fake ip ipv4 mutex poisoned")
            .lookup(u32::from(address))
    }

    /// Returns the name currently mapped to `address` in the IPv6 pool.
    ///
    /// Disabled families, addresses outside the configured range, and
    /// unknown addresses all return `None`. A successful lookup refreshes
    /// the mapping's LRU recency.
    pub fn lookup_ipv6(&self, address: Ipv6Addr) -> Option<Name> {
        self.ipv6
            .as_ref()?
            .lock()
            .expect("fake ip ipv6 mutex poisoned")
            .lookup(u128::from(address))
    }
}

/// Builder for [`FakeIpPool`].
#[must_use]
pub struct FakeIpPoolBuilder {
    ipv4: Option<(u32, u32)>,
    ipv6: Option<(u128, u128)>,
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

    /// Validates the configured ranges and builds the pool.
    ///
    /// At least one address family must be configured. An invalid inclusive
    /// range returns [`Error::InvalidFakeIpRange`].
    pub fn build(self) -> Result<FakeIpPool> {
        let ipv4 = self.ipv4.map(FamilyState::new).transpose()?;
        let ipv6 = self.ipv6.map(FamilyState::new).transpose()?;
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::FakeIpPoolUnconfigured);
        }
        Ok(FakeIpPool {
            ipv4: ipv4.map(Mutex::new),
            ipv6: ipv6.map(Mutex::new),
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

    fn allocate(&mut self, name: Name, salt: u64) -> T {
        if self.forward.contains_key(&name) {
            let recency = self.touch();
            let mapping = self.forward.get_mut(&name).expect("mapping checked above");
            mapping.recency = recency;
            return mapping.address;
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
            },
        );
        address
    }

    fn lookup(&mut self, address: T) -> Option<Name> {
        if address < self.start || address > self.end {
            return None;
        }
        let name = self.reverse.get(&address)?.clone();
        let recency = self.touch();
        self.forward.get_mut(&name)?.recency = recency;
        Some(name)
    }

    fn candidate(&self, hash: u64) -> T {
        T::candidate(self.start, self.end, hash)
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

    #[test]
    fn validates_configuration_and_disabled_families() {
        assert!(matches!(
            FakeIpPool::builder().build(),
            Err(Error::FakeIpPoolUnconfigured)
        ));
        assert!(matches!(
            FakeIpPool::builder()
                .ipv4_range(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1))
                .build(),
            Err(Error::InvalidFakeIpRange)
        ));

        let pool = FakeIpPool::builder()
            .ipv4_range(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
            .build()
            .unwrap();
        assert_eq!(
            pool.allocate_ipv6(name("example.test")).unwrap_err(),
            Error::FakeIpFamilyDisabled
        );
        assert_eq!(pool.lookup_ipv6(Ipv6Addr::LOCALHOST), None);
    }

    #[test]
    fn allocation_is_case_insensitive_reusable_and_reversible() {
        let pool = FakeIpPool::builder()
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
            FakeIpPool::builder()
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
        let pool = FakeIpPool::builder()
            .ipv4_range(start, end)
            .build()
            .unwrap();

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

        let singleton = FakeIpPool::builder()
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
            FakeIpPool::builder()
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
        let pool = FakeIpPool::builder()
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
