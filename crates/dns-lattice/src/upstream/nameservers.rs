//! Runtime-independent selection and failover across upstream servers.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use dns_lattice_core::Result;
use dns_lattice_model::Message;

use super::UpstreamBackend;

/// Selects the first server for a query in a [`NameServerPool`].
///
/// `server_count` is always nonzero. The pool reduces the returned index
/// modulo that count, then tries remaining servers in cyclic registration
/// order on retryable errors. Implementations must be thread-safe and should
/// return promptly; this synchronous method runs once per pool query.
pub trait NameServerBalancer: Send + Sync {
    /// Returns the starting server index for the next query.
    fn select(&self, server_count: usize) -> usize;
}

/// Selects servers in round-robin order, shared across concurrent callers.
#[derive(Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl RoundRobin {
    /// Creates a selector whose first query starts at server zero.
    pub fn new() -> Self {
        Self::default()
    }
}

impl NameServerBalancer for RoundRobin {
    fn select(&self, _server_count: usize) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// A pool of upstream backends with a pluggable starting-server selector.
///
/// By default each call starts at the next server in round-robin order and
/// tries each server at most once,
/// wrapping around on timeout, transport or TLS errors. Other errors and all
/// DNS responses are returned immediately. Dropping the returned future
/// cancels the in-progress backend call. The pool itself creates no tasks,
/// sockets, timers, or runtime; its backends may have their own requirements.
///
/// Register this pool with `ResolverBuilder::backend` as one backend. The
/// resolver's cache and observability apply to the pool as a whole; backend
/// indices in resolver events do not identify individual servers inside it.
pub struct NameServerPool {
    servers: Vec<Box<dyn UpstreamBackend>>,
    balancer: Box<dyn NameServerBalancer>,
}

impl NameServerPool {
    /// Creates a nonempty pool containing `first`.
    pub fn new(first: impl UpstreamBackend + 'static) -> Self {
        Self {
            servers: vec![Box::new(first)],
            balancer: Box::new(RoundRobin::new()),
        }
    }

    /// Adds another server to the pool in rotation order.
    #[must_use]
    pub fn with_backend(mut self, backend: impl UpstreamBackend + 'static) -> Self {
        self.servers.push(Box::new(backend));
        self
    }

    /// Replaces the default round-robin selector.
    #[must_use]
    pub fn with_balancer(mut self, balancer: impl NameServerBalancer + 'static) -> Self {
        self.balancer = Box::new(balancer);
        self
    }

    /// Returns the number of registered servers.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Returns whether the pool is empty. A constructed pool is never empty.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

#[async_trait]
impl UpstreamBackend for NameServerPool {
    async fn resolve(&self, query: &Message) -> Result<Message> {
        let count = self.servers.len();
        let start = self.balancer.select(count) % count;
        let mut last_error = None;
        for offset in 0..count {
            let index = (start + offset) % count;
            match self.servers[index].resolve(query).await {
                Ok(answer) => return Ok(answer),
                Err(error) if crate::engine::is_retryable(&error) => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("a nonempty pool tried at least one server"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use dns_lattice_core::Error;

    use super::*;

    struct Backend {
        id: u16,
        calls: Arc<Mutex<Vec<u16>>>,
        error: Option<Error>,
    }

    #[async_trait]
    impl UpstreamBackend for Backend {
        async fn resolve(&self, query: &Message) -> Result<Message> {
            self.calls.lock().unwrap().push(self.id);
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(query.clone())
        }
    }

    fn backend(id: u16, calls: &Arc<Mutex<Vec<u16>>>, error: Option<Error>) -> Backend {
        Backend {
            id,
            calls: Arc::clone(calls),
            error,
        }
    }

    #[test]
    fn rotates_and_fails_over_without_a_tokio_runtime() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pool = NameServerPool::new(backend(1, &calls, Some(Error::Timeout)))
            .with_backend(backend(2, &calls, None))
            .with_backend(backend(3, &calls, None));
        let query = Message::decode(&[0; 12]).unwrap();
        for _ in 0..3 {
            async_io::block_on(pool.resolve(&query)).unwrap();
        }
        assert_eq!(*calls.lock().unwrap(), [1, 2, 2, 3]);
        assert_eq!(pool.len(), 3);
        assert!(!pool.is_empty());
    }

    #[test]
    fn terminal_error_stops_failover() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pool = NameServerPool::new(backend(1, &calls, Some(Error::NoRoute)))
            .with_backend(backend(2, &calls, None));
        assert_eq!(
            async_io::block_on(pool.resolve(&Message::decode(&[0; 12]).unwrap())),
            Err(Error::NoRoute)
        );
        assert_eq!(*calls.lock().unwrap(), [1]);
    }

    #[test]
    fn custom_balancer_selects_start_and_large_indices_wrap() {
        struct Last;
        impl NameServerBalancer for Last {
            fn select(&self, server_count: usize) -> usize {
                server_count * 2 - 1
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pool = NameServerPool::new(backend(1, &calls, None))
            .with_backend(backend(2, &calls, Some(Error::Timeout)))
            .with_balancer(Last);
        async_io::block_on(pool.resolve(&Message::decode(&[0; 12]).unwrap())).unwrap();
        assert_eq!(*calls.lock().unwrap(), [2, 1]);
    }

    #[test]
    fn round_robin_distributes_concurrent_selections() {
        let selector = Arc::new(RoundRobin::new());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let selector = Arc::clone(&selector);
                std::thread::spawn(move || {
                    let mut counts = [0; 4];
                    for _ in 0..1000 {
                        counts[selector.select(4) % 4] += 1;
                    }
                    counts
                })
            })
            .collect();
        let mut counts = [0; 4];
        for thread in threads {
            for (total, count) in counts.iter_mut().zip(thread.join().unwrap()) {
                *total += count;
            }
        }
        assert_eq!(counts, [1000; 4]);
    }

    #[test]
    fn every_retryable_failure_is_attempted_once() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let pool = NameServerPool::new(backend(1, &calls, Some(Error::Timeout)))
            .with_backend(backend(2, &calls, Some(Error::Transport("offline".into()))));
        assert_eq!(
            async_io::block_on(pool.resolve(&Message::decode(&[0; 12]).unwrap())),
            Err(Error::Transport("offline".into()))
        );
        assert_eq!(*calls.lock().unwrap(), [1, 2]);
    }
}
