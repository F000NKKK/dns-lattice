//! In-flight query coalescing.
//!
//! Concurrent cache misses for the same cache key share one upstream query.
//! The first caller to miss registers a *flight* and becomes its *leader*; every
//! later caller that finds the flight becomes a *follower* and waits for the
//! leader's published outcome instead of querying the upstream itself.
//!
//! # Cancellation
//!
//! Nothing is spawned: the leader runs inside its own `resolve` future. If that
//! future is dropped before it publishes, the [`LeaderGuard`] marks the flight
//! abandoned and unregisters it. Every waiting follower wakes and goes round
//! again; the first to register becomes the new leader, so a cancelled caller
//! never strands the others, and the scheme works on any executor.
//!
//! # Locking
//!
//! A flight shard's lock is held only to look up, register or remove one map
//! entry. No user code, no await and no sink callback runs under it.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dns_lattice_core::Error;
use dns_lattice_model::Message;
use event_listener::{Event, EventListener};

use super::store::CachedAnswer;

/// Number of flight shards: a power of two.
const FLIGHT_SHARDS: usize = 16;

/// What a finished leader hands to its followers.
#[derive(Clone)]
pub(crate) enum Outcome {
    /// A cacheable answer, already normalised for the cache.
    Cached(Arc<CachedAnswer>),
    /// An answer that is not cacheable (for example `SERVFAIL`), as received.
    Raw(Arc<Message>),
    /// The leader's resolution error.
    Failed(Error),
    /// The refresh failed and the leader answers from this expired entry
    /// (serve-stale); followers do the same.
    Stale(Arc<CachedAnswer>),
}

/// The observable state of one flight.
#[derive(Clone)]
enum State {
    /// The leader is still working.
    Pending,
    /// The leader finished.
    Done(Outcome),
    /// The leader was dropped before it finished.
    Abandoned,
}

/// What a waiting follower learned.
pub(crate) enum Wait {
    /// The leader finished.
    Done(Outcome),
    /// The leader was cancelled; the follower must retry.
    Abandoned,
}

struct Registered {
    key: Box<[u8]>,
    flight: Arc<Flight>,
}

struct Flight {
    state: Mutex<State>,
    completed: Event,
}

impl Flight {
    fn new() -> Self {
        Self {
            state: Mutex::new(State::Pending),
            completed: Event::new(),
        }
    }

    fn follow(self: &Arc<Self>) -> Follower {
        Follower {
            listener: self.completed.listen(),
            flight: Arc::clone(self),
        }
    }
}

/// The registry of in-flight queries.
pub(crate) struct Flights {
    shards: [Mutex<HashMap<u64, Registered>>; FLIGHT_SHARDS],
    hasher: RandomState,
}

/// The result of asking to resolve a key.
pub(crate) enum Join {
    /// Another query is already resolving this key.
    Follow(Follower),
    /// The caller is the leader.
    Lead(LeaderGuard),
}

/// A waiting query.
pub(crate) struct Follower {
    flight: Arc<Flight>,
    listener: EventListener,
}

impl Follower {
    /// Waits for the leader to publish or to be dropped.
    pub(crate) async fn wait(self) -> Wait {
        // Registering the listener before the state check prevents a
        // publication between the check and await from being lost.
        let state = lock(&self.flight.state).clone();
        let state = if matches!(state, State::Pending) {
            self.listener.await;
            lock(&self.flight.state).clone()
        } else {
            state
        };
        match state {
            State::Done(outcome) => Wait::Done(outcome),
            State::Pending | State::Abandoned => Wait::Abandoned,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Flights {
    pub(crate) fn new() -> Flights {
        Flights {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            hasher: RandomState::new(),
        }
    }

    /// The keyed hash of `key`.
    pub(crate) fn hash(&self, key: &[u8]) -> u64 {
        self.hasher.hash_one(key)
    }

    fn shard(&self, hash: u64) -> &Mutex<HashMap<u64, Registered>> {
        &self.shards[(hash >> 32) as usize & (FLIGHT_SHARDS - 1)]
    }

    /// Joins the flight for `key`, or registers a new one led by the caller.
    ///
    /// Two different keys whose 64-bit hashes collide never share a flight:
    /// the later one leads an unregistered, private flight.
    pub(crate) fn join_or_lead(self: &Arc<Self>, hash: u64, key: &[u8]) -> Join {
        let mut shard = lock(self.shard(hash));
        match shard.get(&hash) {
            Some(registered) if *registered.key == *key => Join::Follow(registered.flight.follow()),
            Some(_) => Join::Lead(LeaderGuard {
                flights: Arc::clone(self),
                hash,
                flight: Arc::new(Flight::new()),
                registered: false,
                finished: false,
            }),
            None => {
                let flight = Arc::new(Flight::new());
                shard.insert(
                    hash,
                    Registered {
                        key: key.into(),
                        flight: Arc::clone(&flight),
                    },
                );
                Join::Lead(LeaderGuard {
                    flights: Arc::clone(self),
                    hash,
                    flight,
                    registered: true,
                    finished: false,
                })
            }
        }
    }

    /// Removes the flight registered under `hash` if it is the same flight.
    fn unregister(&self, hash: u64, flight: &Arc<Flight>) {
        let mut shard = lock(self.shard(hash));
        if shard
            .get(&hash)
            .is_some_and(|registered| Arc::ptr_eq(&registered.flight, flight))
        {
            shard.remove(&hash);
        }
    }

    /// Number of registered flights.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).len()).sum()
    }
}

/// The leader's handle on its flight. Dropping it without calling
/// [`LeaderGuard::finish`] abandons the flight.
pub(crate) struct LeaderGuard {
    flights: Arc<Flights>,
    hash: u64,
    flight: Arc<Flight>,
    registered: bool,
    finished: bool,
}

impl LeaderGuard {
    /// A follower of this flight, so the leader itself can wait for a result
    /// that a background task will publish.
    pub(crate) fn follower(&self) -> Follower {
        self.flight.follow()
    }

    /// Unregisters the flight, then publishes `outcome` to the followers that
    /// already joined. The outcome is built only if there are any.
    ///
    /// The caller attempts any cache insertion before finishing. If insertion
    /// was rejected or invalidated, a later query may start another flight.
    pub(crate) fn finish(mut self, outcome: impl FnOnce() -> Outcome) {
        if self.registered {
            self.flights.unregister(self.hash, &self.flight);
        }
        // The leader is the only remaining owner when there are no followers.
        if Arc::strong_count(&self.flight) > 1 {
            let outcome = outcome();
            *lock(&self.flight.state) = State::Done(outcome);
            self.finished = true;
            self.flight.completed.notify(usize::MAX);
        } else {
            self.finished = true;
        }
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if self.registered {
            self.flights.unregister(self.hash, &self.flight);
        }
        *lock(&self.flight.state) = State::Abandoned;
        self.flight.completed.notify(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flights() -> Arc<Flights> {
        Arc::new(Flights::new())
    }

    #[tokio::test]
    async fn the_first_caller_leads_and_later_callers_follow() {
        let flights = flights();
        let leader = match flights.join_or_lead(1, b"key") {
            Join::Lead(guard) => guard,
            Join::Follow(_) => panic!("first caller must lead"),
        };
        assert_eq!(flights.len(), 1);
        let follower = match flights.join_or_lead(1, b"key") {
            Join::Follow(follower) => follower,
            Join::Lead(_) => panic!("second caller must follow"),
        };
        leader.finish(|| Outcome::Failed(Error::NoRoute));
        assert_eq!(flights.len(), 0);
        match follower.wait().await {
            Wait::Done(Outcome::Failed(Error::NoRoute)) => {}
            _ => panic!("follower must receive the published outcome"),
        }
    }

    #[tokio::test]
    async fn a_follower_made_from_the_guard_receives_the_outcome() {
        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(3, b"key") else {
            panic!("first caller must lead");
        };
        let follower = leader.follower();
        assert_eq!(flights.len(), 1);
        leader.finish(|| Outcome::Failed(Error::Timeout));
        assert!(matches!(
            follower.wait().await,
            Wait::Done(Outcome::Failed(Error::Timeout))
        ));
    }

    #[tokio::test]
    async fn a_follower_made_from_a_dropped_guard_is_abandoned() {
        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(4, b"key") else {
            panic!("first caller must lead");
        };
        let follower = leader.follower();
        drop(leader);
        assert!(matches!(follower.wait().await, Wait::Abandoned));
    }

    #[tokio::test]
    async fn a_dropped_leader_abandons_its_followers_and_unregisters() {
        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(2, b"key") else {
            panic!("first caller must lead");
        };
        let Join::Follow(follower) = flights.join_or_lead(2, b"key") else {
            panic!("second caller must follow");
        };
        drop(leader);
        assert_eq!(flights.len(), 0);
        assert!(matches!(follower.wait().await, Wait::Abandoned));
        assert!(matches!(flights.join_or_lead(2, b"key"), Join::Lead(_)));
    }

    #[test]
    fn a_hash_collision_never_shares_a_flight() {
        let flights = flights();
        let Join::Lead(first) = flights.join_or_lead(3, b"first") else {
            panic!("first caller must lead");
        };
        let Join::Lead(second) = flights.join_or_lead(3, b"second") else {
            panic!("a different key with the same hash must lead its own flight");
        };
        // The private flight neither registers nor removes the other's entry.
        assert_eq!(flights.len(), 1);
        second.finish(|| Outcome::Failed(Error::NoRoute));
        assert_eq!(flights.len(), 1);
        first.finish(|| Outcome::Failed(Error::NoRoute));
        assert_eq!(flights.len(), 0);
    }

    #[test]
    fn finishing_without_followers_does_not_build_the_outcome() {
        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(4, b"key") else {
            panic!("first caller must lead");
        };
        leader.finish(|| panic!("no follower is waiting"));
    }

    #[test]
    fn a_pending_follower_completes_on_async_io_without_tokio() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(7, b"key") else {
            panic!("first caller must lead");
        };
        let follower = leader.follower();
        let mut wait = Box::pin(follower.wait());
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(wait.as_mut().poll(&mut context), Poll::Pending));
        leader.finish(|| Outcome::Failed(Error::NoRoute));
        assert!(matches!(
            async_io::block_on(wait),
            Wait::Done(Outcome::Failed(Error::NoRoute))
        ));
    }

    #[test]
    fn completion_wakes_each_live_follower_after_another_is_cancelled() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Context, Poll, Wake, Waker};

        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(9, b"key") else {
            panic!("first caller must lead");
        };
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut context = Context::from_waker(&waker);
        let mut first = Box::pin(leader.follower().wait());
        let mut second = Box::pin(leader.follower().wait());
        let mut cancelled = Box::pin(leader.follower().wait());
        assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
        assert!(matches!(second.as_mut().poll(&mut context), Poll::Pending));
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(cancelled);
        leader.finish(|| Outcome::Failed(Error::NoRoute));
        assert_eq!(counter.0.load(Ordering::SeqCst), 2);
        assert!(matches!(
            async_io::block_on(first),
            Wait::Done(Outcome::Failed(Error::NoRoute))
        ));
        assert!(matches!(
            async_io::block_on(second),
            Wait::Done(Outcome::Failed(Error::NoRoute))
        ));
    }

    #[test]
    fn panicking_outcome_builder_abandons_waiting_followers() {
        let flights = flights();
        let Join::Lead(leader) = flights.join_or_lead(8, b"key") else {
            panic!("first caller must lead");
        };
        let follower = leader.follower();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            leader.finish(|| panic!("outcome failed"));
        }));
        assert!(result.is_err());
        assert_eq!(flights.len(), 0);
        assert!(matches!(
            async_io::block_on(follower.wait()),
            Wait::Abandoned
        ));
    }
}
