//! The private answer store: sharded, byte-bounded, S3-FIFO.
//!
//! # Layout
//!
//! The store is split into a power-of-two number of shards, each behind its
//! own [`Mutex`], so concurrent queries only contend when they hit the same
//! shard. A lookup computes one keyed hash of the canonical key bytes
//! ([`KeyBuf`]); the hash's high bits pick the shard and the hash itself is
//! the in-shard map key. Every slot keeps its full key bytes and compares
//! them on a hit, so a 64-bit collision can never serve a mismatched answer:
//! the newer key replaces the older one.
//!
//! # Memory bound
//!
//! Each shard owns `max_bytes / shards` of the budget. Every insert adds the
//! entry's estimated cost ([`entry_cost`]) and then evicts, synchronously and
//! one entry at a time, until the shard is back within its budget. An entry
//! costing more than an eighth of the shard budget is rejected outright. The
//! store is never cleared as a whole to make room.
//!
//! # Eviction
//!
//! Victims are chosen in this order:
//!
//! 1. an entry past its expiry, earliest first (an expiry index per shard);
//! 2. S3-FIFO: a "small" FIFO (10 % of the budget) takes new keys; an entry
//!    that was hit while there moves to the "main" FIFO, any other leaves and
//!    only its hash is remembered in a "ghost" ring; a key found in the ghost
//!    ring on insert enters main directly. Main evicts in FIFO order, giving
//!    an entry that was hit a second chance per hit (at most three).
//!
//! An expired entry is therefore never promoted or reinserted: it is removed
//! before the FIFO queues are consulted.
//!
//! # Locking
//!
//! A lookup holds the shard lock only to find the slot, bump its frequency
//! and clone an [`Arc`]. Building the response from the shared answer happens
//! after the lock is released. A poisoned lock is recovered with
//! [`PoisonError::into_inner`]; no user code runs while a shard is locked.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::hash::{BuildHasher, BuildHasherDefault, Hasher, RandomState};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use dns_lattice_model::{Class, Message, Name, RData, RecordType, ResourceRecord};

/// Longest key: group (4) + type (2) + class (2) + shape (1) + a name's wire
/// form (at most 255).
pub(crate) const MAX_KEY_LEN: usize = 4 + 2 + 2 + 1 + 255;

/// Default shards keep at least this much budget each.
const MIN_SHARD_BYTES: usize = 256 * 1024;

/// Upper bound of the automatic shard count.
const MAX_AUTO_SHARDS: usize = 64;

/// The small queue's share of a shard's budget, in percent.
const SMALL_PERCENT: usize = 10;

/// Highest S3-FIFO frequency an entry can accumulate.
const MAX_FREQ: u8 = 3;

/// An entry costing more than `budget / OVERSIZE_DIVISOR` is not stored.
const OVERSIZE_DIVISOR: usize = 8;

/// Bytes charged for one remembered ghost hash.
const GHOST_COST: usize = 16;

/// The ghost ring may hold `budget / GHOST_DIVISOR` hashes, so at most an
/// eighth of the budget goes to it.
const GHOST_DIVISOR: usize = 128;

/// Bookkeeping charged per entry on top of its key and answer: the slot, its
/// map entry and its expiry-index node.
const ENTRY_OVERHEAD: usize = size_of::<Option<Slot>>() + 64;

/// The allocation header of an [`Arc`].
const ARC_HEADER: usize = 16;

const NIL: u32 = u32::MAX;

/// A normalised cached answer, shared through an [`Arc`] so a hit clones only
/// the pointer while the shard lock is held.
pub(crate) struct CachedAnswer {
    /// The upstream answer with its EDNS OPT record removed (OPT is
    /// per-transaction and never cached, RFC 6891 §6.1.1) and every record
    /// TTL clamped into the entry class's bounds (and, for a negative answer
    /// with an SOA, the SOA TTL rewritten to the negative TTL).
    pub(crate) message: Message,
    /// The instant captured before the upstream call; TTLs count down from
    /// here.
    pub(crate) inserted: Instant,
    /// `inserted` plus the entry TTL; the entry is a miss from this instant.
    pub(crate) expires: Instant,
}

/// The canonical cache key of one query, built in a fixed stack buffer so a
/// lookup does not allocate.
///
/// Layout: group index (`u32`) | type (`u16`) | class (`u16`) | shape bits
/// (`u8`: bit 0 RD, bit 1 DO) | the question name in uncompressed, lowercased
/// wire form.
pub(crate) struct KeyBuf {
    bytes: [u8; MAX_KEY_LEN],
    len: usize,
}

impl KeyBuf {
    /// Builds the key, or returns `None` for a name that does not fit the
    /// wire limits (such a query simply bypasses the cache).
    pub(crate) fn new(
        group: u32,
        rtype: RecordType,
        class: Class,
        recursion_desired: bool,
        dnssec_ok: bool,
        name: &Name,
    ) -> Option<KeyBuf> {
        let mut bytes = [0_u8; MAX_KEY_LEN];
        bytes[0..4].copy_from_slice(&group.to_be_bytes());
        bytes[4..6].copy_from_slice(&type_code(rtype).to_be_bytes());
        bytes[6..8].copy_from_slice(&class_code(class).to_be_bytes());
        bytes[8] = u8::from(recursion_desired) | (u8::from(dnssec_ok) << 1);
        let mut len = 9;
        for label in name.labels() {
            let label_len = u8::try_from(label.len()).ok().filter(|len| *len <= 63)?;
            // Keep one byte for the root label.
            if len + 1 + label.len() + 1 > MAX_KEY_LEN {
                return None;
            }
            bytes[len] = label_len;
            len += 1;
            for byte in label {
                bytes[len] = byte.to_ascii_lowercase();
                len += 1;
            }
        }
        bytes[len] = 0;
        len += 1;
        Some(KeyBuf { bytes, len })
    }

    /// The key bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The wire value of a record type; `Other(n)` and the named variant of the
/// same value share one key.
fn type_code(rtype: RecordType) -> u16 {
    match rtype {
        RecordType::A => 1,
        RecordType::Ns => 2,
        RecordType::Cname => 5,
        RecordType::Soa => 6,
        RecordType::Ptr => 12,
        RecordType::Mx => 15,
        RecordType::Txt => 16,
        RecordType::Aaaa => 28,
        RecordType::Other(value) => value,
    }
}

/// The wire value of a class.
fn class_code(class: Class) -> u16 {
    match class {
        Class::In => 1,
        Class::Ch => 3,
        Class::Other(value) => value,
    }
}

/// A hasher for keys that already are well-mixed 64-bit hashes.
#[derive(Default)]
struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type PassThroughBuild = BuildHasherDefault<PassThrough>;

/// Estimated heap bytes of `name`: its label vector plus every label.
fn name_heap(name: &Name) -> usize {
    name.labels()
        .map(|label| size_of::<Vec<u8>>() + label.len())
        .sum()
}

fn rdata_heap(rdata: &RData) -> usize {
    match rdata {
        RData::A(_) | RData::Aaaa(_) => 0,
        RData::Cname(name) | RData::Ptr(name) | RData::Ns(name) => name_heap(name),
        RData::Txt(strings) => strings
            .iter()
            .map(|string| size_of::<Vec<u8>>() + string.len())
            .sum(),
        RData::Mx { exchange, .. } => name_heap(exchange),
        RData::Soa { mname, rname, .. } => name_heap(mname) + name_heap(rname),
        RData::Unknown { data, .. } => data.len(),
    }
}

fn records_heap(records: &[ResourceRecord]) -> usize {
    size_of_val(records)
        + records
            .iter()
            .map(|record| name_heap(&record.name) + rdata_heap(&record.rdata))
            .sum::<usize>()
}

/// A deterministic structural estimate of the heap `message` occupies.
fn message_heap(message: &Message) -> usize {
    size_of_val(message.questions.as_slice())
        + message
            .questions
            .iter()
            .map(|question| name_heap(&question.name))
            .sum::<usize>()
        + records_heap(&message.answers)
        + records_heap(&message.authorities)
        + records_heap(&message.additionals)
}

/// The estimated bytes one stored entry occupies: fixed bookkeeping, the key,
/// the shared answer and its message heap. Computed once, on insert.
pub(crate) fn entry_cost(key_len: usize, entry: &CachedAnswer) -> usize {
    ENTRY_OVERHEAD + key_len + ARC_HEADER + size_of::<CachedAnswer>() + message_heap(&entry.message)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Queue {
    Small,
    Main,
}

struct Slot {
    key: Box<[u8]>,
    hash: u64,
    entry: Arc<CachedAnswer>,
    cost: usize,
    expires: Instant,
    freq: u8,
    queue: Queue,
    prev: u32,
    next: u32,
}

/// An intrusive FIFO of slab indices; `head` is the oldest.
struct List {
    head: u32,
    tail: u32,
    bytes: usize,
}

impl List {
    const fn new() -> Self {
        List {
            head: NIL,
            tail: NIL,
            bytes: 0,
        }
    }
}

struct Shard {
    budget: usize,
    small_target: usize,
    ghost_cap: usize,
    map: HashMap<u64, u32, PassThroughBuild>,
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
    small: List,
    main: List,
    /// `(expires, slot)` of every live slot, earliest first.
    expiry: BTreeSet<(Instant, u32)>,
    /// Remembered hashes mapped to the sequence number of their ring entry.
    ghost: HashMap<u64, u64, PassThroughBuild>,
    ghost_order: VecDeque<(u64, u64)>,
    ghost_seq: u64,
}

impl Shard {
    fn new(budget: usize) -> Self {
        Shard {
            budget,
            small_target: budget / (100 / SMALL_PERCENT),
            ghost_cap: budget / GHOST_DIVISOR,
            map: HashMap::default(),
            slots: Vec::new(),
            free: Vec::new(),
            small: List::new(),
            main: List::new(),
            expiry: BTreeSet::new(),
            ghost: HashMap::default(),
            ghost_order: VecDeque::new(),
            ghost_seq: 0,
        }
    }

    fn total_bytes(&self) -> usize {
        self.small.bytes + self.main.bytes + self.ghost_order.len() * GHOST_COST
    }

    fn slot(&self, index: u32) -> &Slot {
        self.slots[index as usize]
            .as_ref()
            .expect("slot index refers to a live slot")
    }

    fn slot_mut(&mut self, index: u32) -> &mut Slot {
        self.slots[index as usize]
            .as_mut()
            .expect("slot index refers to a live slot")
    }

    fn list_mut(&mut self, queue: Queue) -> &mut List {
        match queue {
            Queue::Small => &mut self.small,
            Queue::Main => &mut self.main,
        }
    }

    fn push_back(&mut self, index: u32, queue: Queue) {
        let tail = self.list_mut(queue).tail;
        let cost = {
            let slot = self.slot_mut(index);
            slot.prev = tail;
            slot.next = NIL;
            slot.queue = queue;
            slot.cost
        };
        if tail != NIL {
            self.slot_mut(tail).next = index;
        }
        let list = self.list_mut(queue);
        if tail == NIL {
            list.head = index;
        }
        list.tail = index;
        list.bytes += cost;
    }

    fn unlink(&mut self, index: u32) {
        let (prev, next, queue, cost) = {
            let slot = self.slot(index);
            (slot.prev, slot.next, slot.queue, slot.cost)
        };
        if prev != NIL {
            self.slot_mut(prev).next = next;
        }
        if next != NIL {
            self.slot_mut(next).prev = prev;
        }
        let list = self.list_mut(queue);
        if list.head == index {
            list.head = next;
        }
        if list.tail == index {
            list.tail = prev;
        }
        list.bytes -= cost;
    }

    /// Removes a live slot from every index and frees it.
    fn remove_slot(&mut self, index: u32) -> Slot {
        self.unlink(index);
        let slot = self.slots[index as usize]
            .take()
            .expect("slot index refers to a live slot");
        if self.map.get(&slot.hash) == Some(&index) {
            self.map.remove(&slot.hash);
        }
        self.expiry.remove(&(slot.expires, index));
        self.free.push(index);
        slot
    }

    fn push_ghost(&mut self, hash: u64) {
        if self.ghost_cap == 0 {
            return;
        }
        self.ghost_seq += 1;
        self.ghost.insert(hash, self.ghost_seq);
        self.ghost_order.push_back((hash, self.ghost_seq));
        while self.ghost_order.len() > self.ghost_cap {
            if let Some((old_hash, old_seq)) = self.ghost_order.pop_front()
                && self.ghost.get(&old_hash) == Some(&old_seq)
            {
                self.ghost.remove(&old_hash);
            }
        }
    }

    fn get(&mut self, hash: u64, key: &[u8], now: Instant) -> Option<Arc<CachedAnswer>> {
        let index = *self.map.get(&hash)?;
        let slot = self.slots[index as usize].as_mut()?;
        if *slot.key != *key {
            return None;
        }
        if slot.expires <= now {
            let removed = self.remove_slot(index);
            if removed.freq > 0 {
                self.push_ghost(removed.hash);
            }
            return None;
        }
        slot.freq = (slot.freq + 1).min(MAX_FREQ);
        Some(Arc::clone(&slot.entry))
    }

    fn insert(&mut self, hash: u64, key: &[u8], entry: Arc<CachedAnswer>, now: Instant) -> bool {
        let cost = entry_cost(key.len(), &entry);
        // The newer answer replaces whatever the hash maps to; a key that was
        // reused stays in main across a refresh.
        let mut reused = false;
        if let Some(&old_index) = self.map.get(&hash) {
            let old = self.remove_slot(old_index);
            reused = *old.key == *key && (old.freq > 0 || old.queue == Queue::Main);
        }
        if cost > self.budget / OVERSIZE_DIVISOR {
            return false;
        }
        let remembered = self.ghost.remove(&hash).is_some();
        let queue = if reused || remembered {
            Queue::Main
        } else {
            Queue::Small
        };

        let slot = Slot {
            key: key.into(),
            hash,
            expires: entry.expires,
            entry,
            cost,
            freq: 0,
            queue,
            prev: NIL,
            next: NIL,
        };
        let index = match self.free.pop() {
            Some(index) => {
                self.slots[index as usize] = Some(slot);
                index
            }
            None => {
                self.slots.push(Some(slot));
                u32::try_from(self.slots.len() - 1).unwrap_or(NIL)
            }
        };
        if index == NIL {
            // More than u32::MAX slots cannot fit any realistic budget.
            self.slots.pop();
            return false;
        }
        self.map.insert(hash, index);
        let expires = self.slot(index).expires;
        self.expiry.insert((expires, index));
        self.push_back(index, queue);

        self.make_room(now);
        true
    }

    /// Evicts until the shard is back within its budget.
    fn make_room(&mut self, now: Instant) {
        while self.total_bytes() > self.budget {
            if let Some(&(expires, index)) = self.expiry.first()
                && expires <= now
            {
                self.remove_slot(index);
                continue;
            }
            if !self.evict_one() {
                break;
            }
        }
    }

    /// One S3-FIFO step; `false` when there is nothing left to evict.
    fn evict_one(&mut self) -> bool {
        let from_small = self.small.bytes > self.small_target || self.main.head == NIL;
        if from_small {
            let index = self.small.head;
            if index == NIL {
                return false;
            }
            if self.slot(index).freq > 0 {
                self.unlink(index);
                self.slot_mut(index).freq = 0;
                self.push_back(index, Queue::Main);
            } else {
                let removed = self.remove_slot(index);
                self.push_ghost(removed.hash);
            }
        } else {
            let index = self.main.head;
            if self.slot(index).freq > 0 {
                self.unlink(index);
                let slot = self.slot_mut(index);
                slot.freq -= 1;
                self.push_back(index, Queue::Main);
            } else {
                self.remove_slot(index);
            }
        }
        true
    }
}

fn lock(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The shard count used when none is configured: four per core, a power of
/// two in `1..=64`, reduced until every shard keeps at least 256 KiB.
pub(crate) fn default_shard_count(max_bytes: usize, parallelism: usize) -> usize {
    let mut shards = parallelism
        .max(1)
        .saturating_mul(4)
        .next_power_of_two()
        .min(MAX_AUTO_SHARDS);
    while shards > 1 && max_bytes / shards < MIN_SHARD_BYTES {
        shards /= 2;
    }
    shards
}

/// The sharded, byte-bounded answer store.
pub(crate) struct Store {
    shards: Box<[Mutex<Shard>]>,
    mask: usize,
    hasher: RandomState,
}

impl Store {
    /// Creates a store bounded to about `max_bytes`, split over `shards`
    /// shards (a power of two) or an automatic count.
    pub(crate) fn new(max_bytes: usize, shards: Option<usize>) -> Store {
        let count = match shards {
            Some(count) => count.max(1).next_power_of_two(),
            None => {
                let parallelism = std::thread::available_parallelism().map_or(1, |n| n.get());
                default_shard_count(max_bytes, parallelism)
            }
        };
        let budget = max_bytes / count;
        Store {
            shards: (0..count).map(|_| Mutex::new(Shard::new(budget))).collect(),
            mask: count - 1,
            hasher: RandomState::new(),
        }
    }

    /// The keyed hash of `key`, computed once per lookup.
    pub(crate) fn hash(&self, key: &[u8]) -> u64 {
        self.hasher.hash_one(key)
    }

    fn shard(&self, hash: u64) -> &Mutex<Shard> {
        // The high bits choose the shard; the map inside uses the whole hash.
        &self.shards[(hash >> 32) as usize & self.mask]
    }

    /// Returns the fresh entry for `key`, cloning only its [`Arc`] under the
    /// shard lock. An entry found expired at `now` is removed.
    pub(crate) fn get(&self, hash: u64, key: &[u8], now: Instant) -> Option<Arc<CachedAnswer>> {
        lock(self.shard(hash)).get(hash, key, now)
    }

    /// Stores `entry` under `key`, evicting until its shard is within budget.
    /// Returns `false` when the entry is too large to be stored (more than an
    /// eighth of a shard's budget); nothing else is evicted in that case.
    #[cfg(test)]
    pub(crate) fn insert(
        &self,
        hash: u64,
        key: &[u8],
        entry: Arc<CachedAnswer>,
        now: Instant,
    ) -> bool {
        lock(self.shard(hash)).insert(hash, key, entry, now)
    }

    /// Like [`Store::insert`], but stores only if `allowed` returns `true`,
    /// evaluated while the shard lock is held. A concurrent purge that bumps
    /// its epoch and then locks the shard therefore either sees this entry
    /// and removes it, or makes `allowed` fail first.
    pub(crate) fn insert_if(
        &self,
        hash: u64,
        key: &[u8],
        entry: Arc<CachedAnswer>,
        now: Instant,
        allowed: impl FnOnce() -> bool,
    ) -> bool {
        let mut shard = lock(self.shard(hash));
        allowed() && shard.insert(hash, key, entry, now)
    }

    /// Number of entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).map.len()).sum()
    }

    /// Estimated bytes in use (entries plus ghost hashes).
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| lock(shard).total_bytes())
            .sum()
    }

    /// Whether every shard's lock is currently free.
    #[cfg(test)]
    pub(crate) fn all_unlocked(&self) -> bool {
        self.shards.iter().all(|shard| shard.try_lock().is_ok())
    }

    /// Whether `check` holds for every stored entry.
    #[cfg(test)]
    pub(crate) fn all_entries(&self, check: impl Fn(&CachedAnswer) -> bool) -> bool {
        self.shards.iter().all(|shard| {
            lock(shard)
                .slots
                .iter()
                .flatten()
                .all(|slot| check(&slot.entry))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dns_lattice_model::{Header, Opcode, Rcode};

    use super::*;

    fn message(txt_bytes: usize) -> Message {
        let name = Name::from_ascii("example.com").unwrap();
        let rdata = if txt_bytes == 0 {
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        } else {
            RData::Txt(vec![vec![b'x'; txt_bytes]])
        };
        Message {
            header: Header {
                id: 1,
                qr: true,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                rcode: Rcode::NoError,
            },
            questions: vec![],
            answers: vec![ResourceRecord {
                name,
                rtype: RecordType::A,
                class: Class::In,
                ttl: 300,
                rdata,
            }],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn entry(base: Instant, ttl: u64, txt_bytes: usize) -> Arc<CachedAnswer> {
        Arc::new(CachedAnswer {
            message: message(txt_bytes),
            inserted: base,
            expires: base + Duration::from_secs(ttl),
        })
    }

    fn key(i: usize) -> Vec<u8> {
        format!("key-{i:08}").into_bytes()
    }

    /// The cost of an entry built by `entry(_, _, 0)` under `key(0)`.
    fn small_cost(base: Instant) -> usize {
        entry_cost(key(0).len(), &entry(base, 10, 0))
    }

    fn put(store: &Store, i: usize, ttl: u64, now: Instant) -> bool {
        let k = key(i);
        store.insert(store.hash(&k), &k, entry(now, ttl, 0), now)
    }

    fn fetch(store: &Store, i: usize, now: Instant) -> bool {
        let k = key(i);
        store.get(store.hash(&k), &k, now).is_some()
    }

    #[test]
    fn bytes_never_exceed_the_budget_after_any_insert() {
        let base = Instant::now();
        let budget = 64 * 1024;
        let store = Store::new(budget, Some(1));
        for i in 0..2_000 {
            assert!(put(&store, i, 300, base));
            assert!(store.bytes() <= budget, "insert {i}: {}", store.bytes());
        }
        let capacity = budget / small_cost(base);
        assert!(store.len() < 2_000, "old entries were evicted");
        assert!(store.len() > capacity / 2, "the budget is actually used");
    }

    #[test]
    fn eviction_is_incremental_and_never_flushes_the_cache() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        let mut previous = 0;
        let mut at_bound = 0;
        for i in 0..1_000 {
            put(&store, i, 300, base);
            let len = store.len();
            if i > 300 {
                // After the bound is reached the count only wobbles by one
                // entry per insert; it never drops to a fraction.
                assert!(len + 1 >= previous, "insert {i}: {previous} -> {len}");
                at_bound = at_bound.max(len);
            }
            previous = len;
        }
        assert!(at_bound > 0 && store.len() * 2 > at_bound);
    }

    #[test]
    fn an_oversized_entry_is_rejected_without_evicting_others() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        for i in 0..5 {
            assert!(put(&store, i, 300, base));
        }
        let before = (store.len(), store.bytes());

        let k = key(99);
        let huge = entry(base, 300, 20_000);
        assert!(entry_cost(k.len(), &huge) > 64 * 1024 / OVERSIZE_DIVISOR);
        assert!(!store.insert(store.hash(&k), &k, huge, base));
        assert_eq!((store.len(), store.bytes()), before);
        assert!(!fetch(&store, 99, base));
        for i in 0..5 {
            assert!(fetch(&store, i, base));
        }

        // An entry just under the limit is stored.
        let k = key(98);
        let fits = entry(base, 300, 6_000);
        assert!(entry_cost(k.len(), &fits) <= 64 * 1024 / OVERSIZE_DIVISOR);
        assert!(store.insert(store.hash(&k), &k, fits, base));
        assert!(fetch(&store, 98, base));
    }

    #[test]
    fn a_zero_budget_shard_stores_nothing() {
        let base = Instant::now();
        let store = Store::new(0, Some(1));
        assert!(!put(&store, 0, 300, base));
        assert_eq!((store.len(), store.bytes()), (0, 0));
    }

    #[test]
    fn expired_entries_are_evicted_before_live_ones() {
        let base = Instant::now();
        let cost = small_cost(base);
        // Room for ten entries and a bit.
        let budget = cost * 10 + cost / 2;
        let store = Store::new(budget, Some(1));
        // Interleave long-lived (even) and short-lived (odd) entries.
        for i in 0..10 {
            let ttl = if i % 2 == 0 { 1_000 } else { 10 };
            assert!(put(&store, i, ttl, base));
        }
        assert_eq!(store.len(), 10);

        let later = base + Duration::from_secs(20);
        for i in 10..15 {
            assert!(put(&store, i, 1_000, later));
        }
        // Each insert evicted exactly one entry, and each was an expired one.
        assert_eq!(store.len(), 10);
        assert!(store.bytes() <= budget);
        for i in (0..10).filter(|i| i % 2 == 0).chain(10..15) {
            assert!(fetch(&store, i, later), "live entry {i} survived");
        }
        for i in (0..10).filter(|i| i % 2 == 1) {
            assert!(!fetch(&store, i, later), "expired entry {i} was evicted");
        }
    }

    #[test]
    fn an_expired_entry_is_not_promoted_to_main() {
        let base = Instant::now();
        let cost = small_cost(base);
        let store = Store::new(cost * 10 + cost / 2, Some(1));
        assert!(put(&store, 0, 10, base));
        assert!(fetch(&store, 0, base), "a hit gives it a second chance");
        let later = base + Duration::from_secs(10);
        for i in 1..30 {
            put(&store, i, 1_000, later);
        }
        {
            let shard = lock(&store.shards[0]);
            let wanted = key(0);
            assert!(
                shard
                    .slots
                    .iter()
                    .flatten()
                    .all(|slot| *slot.key != *wanted),
                "the expired entry is gone from both queues"
            );
            assert_eq!(shard.main.bytes, 0, "nothing was promoted to main");
        }
        assert!(!fetch(&store, 0, later));
    }

    #[test]
    fn a_lookup_removes_the_expired_entry_it_finds() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        put(&store, 0, 10, base);
        assert_eq!(store.len(), 1);
        assert!(fetch(&store, 0, base + Duration::from_secs(9)));
        assert!(!fetch(&store, 0, base + Duration::from_secs(10)));
        // The entry was reused, so only its hash is remembered (one ghost
        // slot); none of its answer is kept.
        assert_eq!((store.len(), store.bytes()), (0, GHOST_COST));
    }

    #[test]
    fn a_flood_of_one_hit_wonders_keeps_the_reused_set() {
        let base = Instant::now();
        let cost = small_cost(base);
        let budget = cost * 100;
        let store = Store::new(budget, Some(1));
        let hot = 20;
        for i in 0..hot {
            put(&store, i, 3_600, base);
        }
        for i in 0..hot {
            assert!(fetch(&store, i, base));
            assert!(fetch(&store, i, base));
        }
        for i in 1_000..6_000 {
            put(&store, i, 3_600, base);
            assert!(store.bytes() <= budget);
        }
        for i in 0..hot {
            assert!(fetch(&store, i, base), "hot entry {i} survived the flood");
        }
        assert!(!fetch(&store, 1_000, base), "early flood entries are gone");
    }

    #[test]
    fn a_key_remembered_by_the_ghost_ring_enters_main() {
        let base = Instant::now();
        let cost = small_cost(base);
        let store = Store::new(cost * 20, Some(1));
        put(&store, 0, 3_600, base);
        for i in 1..60 {
            put(&store, i, 3_600, base);
        }
        assert!(!fetch(&store, 0, base), "evicted from small unreused");
        put(&store, 0, 3_600, base);
        let shard = lock(&store.shards[0]);
        let slot = shard
            .slots
            .iter()
            .flatten()
            .find(|slot| slot.key == key(0).into_boxed_slice())
            .unwrap();
        assert!(slot.queue == Queue::Main, "a remembered key skips small");
    }

    #[test]
    fn a_refreshed_hot_key_stays_in_main() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        put(&store, 0, 10, base);
        assert!(fetch(&store, 0, base));
        let later = base + Duration::from_secs(10);
        put(&store, 0, 10, later);
        let shard = lock(&store.shards[0]);
        let slot = shard.slots.iter().flatten().next().unwrap();
        assert!(slot.queue == Queue::Main);
        assert_eq!(shard.map.len(), 1);
    }

    #[test]
    fn replacing_a_key_keeps_the_accounting_exact() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        put(&store, 0, 300, base);
        let one = store.bytes();
        for _ in 0..10 {
            put(&store, 0, 300, base);
        }
        assert_eq!((store.len(), store.bytes()), (1, one));
    }

    #[test]
    fn a_hash_collision_replaces_the_older_key_and_never_serves_a_mismatch() {
        let base = Instant::now();
        let store = Store::new(64 * 1024, Some(1));
        let (a, b) = (key(1), key(2));
        let hash = 0xDEAD_BEEF_u64;
        assert!(store.insert(hash, &a, entry(base, 300, 0), base));
        assert!(store.get(hash, &b, base).is_none(), "wrong key, same hash");
        assert!(store.get(hash, &a, base).is_some());

        assert!(store.insert(hash, &b, entry(base, 300, 0), base));
        assert_eq!(store.len(), 1);
        assert!(store.get(hash, &a, base).is_none(), "the older key is gone");
        assert!(store.get(hash, &b, base).is_some());
    }

    #[test]
    fn keys_spread_over_every_shard() {
        let base = Instant::now();
        let store = Store::new(16 * 1024 * 1024, Some(8));
        let total = 4_000;
        for i in 0..total {
            assert!(put(&store, i, 300, base));
        }
        let lens: Vec<usize> = store
            .shards
            .iter()
            .map(|shard| lock(shard).map.len())
            .collect();
        assert_eq!(lens.len(), 8);
        assert_eq!(lens.iter().sum::<usize>(), total);
        // 500 expected per shard; 250 is more than ten standard deviations
        // below, so a keyed hash never trips it.
        assert!(lens.iter().all(|len| *len > 250), "{lens:?}");
    }

    #[test]
    fn the_shard_count_is_a_power_of_two_and_keeps_shards_large() {
        let mib = 1024 * 1024;
        assert_eq!(default_shard_count(16 * mib, 1), 4);
        assert_eq!(default_shard_count(16 * mib, 3), 16);
        assert_eq!(default_shard_count(16 * mib, 8), 32);
        assert_eq!(default_shard_count(16 * mib, 64), 64);
        assert_eq!(default_shard_count(16 * mib, 1_000), 64);
        assert_eq!(default_shard_count(mib, 8), 4);
        assert_eq!(default_shard_count(100 * 1024, 8), 1);
        assert_eq!(default_shard_count(0, 0), 1);
        let store = Store::new(16 * mib, Some(5));
        assert_eq!(store.shards.len(), 8);
        let store = Store::new(16 * mib, None);
        assert!(store.shards.len().is_power_of_two());
    }

    #[test]
    fn concurrent_hits_all_succeed_and_do_not_block_each_other() {
        let base = Instant::now();
        let store = Arc::new(Store::new(16 * 1024 * 1024, Some(4)));
        for i in 0..100 {
            put(&store, i, 300, base);
        }
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut hits = 0_usize;
                    for round in 0..2_000 {
                        if fetch(&store, (round * 7 + t) % 100, base) {
                            hits += 1;
                        }
                    }
                    hits
                })
            })
            .collect();
        let hits: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(hits, 8 * 2_000);
        assert!(store.all_unlocked());
        assert_eq!(store.len(), 100);
    }

    #[test]
    fn concurrent_inserts_respect_the_bound() {
        let base = Instant::now();
        let budget = 256 * 1024;
        let store = Arc::new(Store::new(budget, Some(4)));
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..2_000 {
                        put(&store, t * 100_000 + i, 300, base);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert!(store.bytes() <= budget);
        assert!(store.len() > 0);
    }

    fn key_for(name: &str, rd: bool, dnssec_ok: bool) -> Vec<u8> {
        KeyBuf::new(
            1,
            RecordType::A,
            Class::In,
            rd,
            dnssec_ok,
            &Name::from_ascii(name).unwrap(),
        )
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn the_key_is_case_insensitive_and_separates_every_identity_part() {
        let base = key_for("example.com", true, false);
        assert_eq!(base, key_for("ExAmPlE.CoM.", true, false));
        assert_ne!(base, key_for("example.org", true, false));
        assert_ne!(base, key_for("www.example.com", true, false));
        assert_ne!(base, key_for("example.com", false, false), "RD");
        assert_ne!(base, key_for("example.com", true, true), "DO");
        // Label boundaries are part of the key: "a.bc" is not "ab.c".
        assert_ne!(key_for("a.bc", true, false), key_for("ab.c", true, false));

        let name = Name::from_ascii("example.com").unwrap();
        let key = |group, rtype, class| {
            KeyBuf::new(group, rtype, class, true, false, &name)
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        let reference = key(1, RecordType::A, Class::In);
        assert_ne!(reference, key(2, RecordType::A, Class::In), "group");
        assert_ne!(reference, key(1, RecordType::Aaaa, Class::In), "type");
        assert_ne!(reference, key(1, RecordType::A, Class::Ch), "class");
        assert_eq!(
            key(1, RecordType::Other(1), Class::Other(1)),
            reference,
            "equal wire values share a key"
        );
    }

    #[test]
    fn the_root_name_and_the_longest_name_fit_the_key_buffer() {
        let root = KeyBuf::new(0, RecordType::Ns, Class::In, true, false, &Name::root()).unwrap();
        assert_eq!(root.as_bytes().len(), 10);
        let label = "a".repeat(63);
        let long = format!("{label}.{label}.{label}.{}", "b".repeat(61));
        let name = Name::from_ascii(&long).unwrap();
        let key = KeyBuf::new(0, RecordType::A, Class::In, true, false, &name).unwrap();
        assert_eq!(key.as_bytes().len(), MAX_KEY_LEN);
    }

    #[test]
    fn cost_grows_with_the_answer_and_covers_the_key() {
        let base = Instant::now();
        let small = entry_cost(10, &entry(base, 10, 0));
        assert!(entry_cost(100, &entry(base, 10, 0)) == small + 90);
        assert!(entry_cost(10, &entry(base, 10, 1_000)) >= small + 1_000);
    }
}
