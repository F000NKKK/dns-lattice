//! Optional, non-authoritative resolver observability.
//!
//! [`ObservabilitySink`](crate::observability::ObservabilitySink) receives
//! immutable, synchronous [`ObserveEvent`](crate::observability::ObserveEvent)
//! values after each resolver transition. Sinks are advisory only: a panic is
//! isolated, and a sink cannot alter routing, caching, retries, or answers.
//! Events contain no client address, resolver/backend handle, or error text.
//!
//! Signals that are not part of the ordered stream arrive through defaulted
//! methods: [`CacheEvent`](crate::observability::CacheEvent) through
//! `record_cache`, and the connection lifecycle of pooled upstream backends,
//! [`PoolEvent`](crate::observability::PoolEvent), through
//! `record_upstream_pool`. A backend is not built by the resolver, so its sink
//! is attached with
//! [`PoolConfig::observability_sink`](crate::upstream::PoolConfig::observability_sink).

use crate::model::{Class, Name, Rcode, RecordType, UpstreamGroupId};

/// A synchronous, thread-safe observer for resolver events.
///
/// Implementations must not re-enter the same resolver. The resolver invokes
/// this callback without holding its cache lock; a callback panic is ignored.
pub trait ObservabilitySink: Send + Sync {
    /// Receives one immutable, ordered event.
    fn record(&self, event: &ObserveEvent);

    /// Receives one immutable [`CacheEvent`], a cache signal that is not part
    /// of the ordered [`ObserveEvent`] stream. The default implementation
    /// ignores it, so existing sinks keep working unchanged.
    ///
    /// The same rules as [`ObservabilitySink::record`] apply: it is called
    /// without any resolver lock held and a panic is ignored.
    fn record_cache(&self, _event: &CacheEvent) {}

    /// Receives one immutable [`PoolEvent`], a connection-pool signal of an
    /// upstream backend that is not part of the ordered [`ObserveEvent`]
    /// stream. The default implementation ignores it, so existing sinks keep
    /// working unchanged.
    ///
    /// A backend has no handle to the resolver's sink, so the sink that
    /// receives these events is the one given to
    /// [`PoolConfig::observability_sink`](crate::upstream::PoolConfig::observability_sink).
    /// The method is called from the backend's own tasks, or from the task of
    /// a query, without any pool lock held; a panic is ignored. It must not
    /// block, because it runs on the Tokio runtime.
    fn record_upstream_pool(&self, _event: &PoolEvent) {}
}

/// Why a pooled upstream connection was closed, reported by
/// [`PoolEvent::ConnectionClosed`].
///
/// The enum is `#[non_exhaustive]`: later releases may add variants, so match
/// with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PoolCloseReason {
    /// The connection had no query for the pool's idle timeout.
    Idle,
    /// The connection reached its maximum lifetime and was rotated.
    Lifetime,
    /// The upstream closed or reset the connection (end of stream, a TCP
    /// reset, a QUIC or HTTP/3 `CONNECTION_CLOSE`).
    PeerClosed,
    /// The connection failed for another reason: an I/O error, a QUIC
    /// transport error, a malformed frame, too many unexpected frames, or
    /// repeated queries that timed out on it.
    Error,
    /// The backend was dropped and closed its connections.
    Shutdown,
    /// The transport did not say why the connection ended. The DoH backend
    /// reports this for a connection its HTTP client closed without being
    /// rotated or shut down (the client does not distinguish an idle timeout
    /// from a closure by the server).
    Other,
}

/// Immutable connection-pool signal of an upstream backend, delivered through
/// [`ObservabilitySink::record_upstream_pool`].
///
/// Only connection lifecycle and retries are reported; there is no event per
/// query (the counters of
/// [`PoolStats`](crate::upstream::PoolStats) cover those). Events carry the
/// transport and the upstream's address, never error text, a client address or
/// a query name. A connection that is neither opened nor closed by the pool
/// (a backend with [`PoolConfig::disabled`](crate::upstream::PoolConfig::disabled))
/// produces no events.
///
/// The enum and every variant are `#[non_exhaustive]`: later releases may add
/// variants and fields, so match with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PoolEvent {
    /// The pool established a connection to the upstream.
    #[non_exhaustive]
    ConnectionOpened {
        /// The backend's transport: `"tcp"`, `"dot"`, `"doh"`, `"doh3"` or
        /// `"doq"`.
        transport: &'static str,
        /// The upstream, as `host:port` (the socket address for TCP, DoT,
        /// DoQ and DoH3, the URI authority for DoH).
        server: String,
    },
    /// A pooled connection ended. It is reported once per opened connection,
    /// whichever way it ended.
    #[non_exhaustive]
    ConnectionClosed {
        /// The backend's transport: `"tcp"`, `"dot"`, `"doh"`, `"doh3"` or
        /// `"doq"`.
        transport: &'static str,
        /// The upstream, as `host:port`.
        server: String,
        /// Why the connection ended.
        reason: PoolCloseReason,
    },
    /// A query was sent again on a fresh connection because the reused
    /// connection it was on failed at the connection level.
    #[non_exhaustive]
    QueryRetried {
        /// The backend's transport: `"tcp"`, `"dot"`, `"doh"`, `"doh3"` or
        /// `"doq"`.
        transport: &'static str,
        /// The upstream, as `host:port`.
        server: String,
    },
}

/// Immutable cache signal emitted by an opted-in resolver through
/// [`ObservabilitySink::record_cache`].
///
/// The enum and every variant are `#[non_exhaustive]`: later releases may add
/// variants and fields, so match with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheEvent {
    /// The query joined another query's in-flight upstream call instead of
    /// making its own. It is emitted after [`ObserveEvent::CacheMiss`] and
    /// before the terminal [`ObserveEvent::Completed`] or
    /// [`ObserveEvent::Failed`]; the query emits no
    /// [`ObserveEvent::UpstreamAttempt`] or [`ObserveEvent::UpstreamOutcome`].
    #[non_exhaustive]
    Coalesced {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group whose upstream call was joined.
        group: UpstreamGroupId,
    },
    /// The query was answered with an expired answer (see
    /// [`ServeStale`](crate::cache::ServeStale)). It is emitted before the
    /// terminal [`ObserveEvent::Completed`]: either after
    /// [`ObserveEvent::CacheHit`] (the entry is inside the recheck window of a
    /// failed refresh and the upstream was not asked) or after
    /// [`ObserveEvent::CacheMiss`] (the refresh failed or timed out).
    #[non_exhaustive]
    StaleServed {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group whose cache scope held the answer.
        group: UpstreamGroupId,
    },
    /// The query was answered with a remembered upstream failure (see
    /// [`FailureCache`](crate::cache::FailureCache)) without an upstream call.
    /// It is emitted after [`ObserveEvent::CacheHit`] and before the terminal
    /// [`ObserveEvent::Completed`] (a cached `SERVFAIL`/`REFUSED` answer) or
    /// [`ObserveEvent::Failed`] (a cached error).
    #[non_exhaustive]
    FailureServed {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group whose cache scope held the failure.
        group: UpstreamGroupId,
    },
    /// A background refresh of a cache entry began: a popular entry about to
    /// expire (see [`Prefetch`](crate::cache::Prefetch)) or an expired one a
    /// query handed over under a
    /// [`ServeStale::client_timeout`](crate::cache::ServeStale::client_timeout).
    /// It belongs to no client query:
    /// its `correlation_id` is fresh, shared only with the matching
    /// [`CacheEvent::RefreshCompleted`], and no [`ObserveEvent`] carries it.
    #[non_exhaustive]
    RefreshStarted {
        /// Opaque identifier of this refresh.
        correlation_id: u64,
        /// The group whose upstream backends are queried.
        group: UpstreamGroupId,
    },
    /// A background refresh finished. It is not emitted when the refresh is
    /// cancelled because the resolver was dropped.
    #[non_exhaustive]
    RefreshCompleted {
        /// The identifier of the matching [`CacheEvent::RefreshStarted`].
        correlation_id: u64,
        /// The group whose upstream backends were queried.
        group: UpstreamGroupId,
        /// Whether a fresh answer replaced the cached entry. `false` after an
        /// upstream error, an answer that cannot be cached, or a flush that
        /// happened while the refresh was running.
        refreshed: bool,
    },
}

/// Immutable event emitted by an opted-in resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveEvent {
    /// A query entered the resolver. Identity fields are absent only when it
    /// has no first question and therefore cannot be routed.
    QueryReceived {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The first question's name, absent only when unroutable.
        name: Option<Name>,
        /// The first question's record type, absent only when unroutable.
        rtype: Option<RecordType>,
        /// The first question's class, absent only when unroutable.
        class: Option<Class>,
    },
    /// Fake IP returned a terminal local answer.
    FakeIpTerminal {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
    },
    /// Static split-DNS selected a tentative group, if any.
    StaticRoute {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The tentatively selected group, or `None` if no policy matched.
        group: Option<UpstreamGroupId>,
    },
    /// The optional hook's selection-only decision.
    HookDecision {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The hook's bounded outcome.
        decision: HookObserveDecision,
    },
    /// The route-scoped cache supplied an answer.
    CacheHit {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group whose cache scope was consulted.
        group: UpstreamGroupId,
    },
    /// The route-scoped cache did not supply an answer.
    CacheMiss {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group whose cache scope was consulted.
        group: UpstreamGroupId,
    },
    /// One backend is about to be called; its index is registration order.
    UpstreamAttempt {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group the attempted backend belongs to.
        group: UpstreamGroupId,
        /// The backend's position within the group's registration order.
        backend_index: usize,
    },
    /// One backend completed without exposing an error string or handle.
    UpstreamOutcome {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The group the completed backend belongs to.
        group: UpstreamGroupId,
        /// The backend's position within the group's registration order.
        backend_index: usize,
        /// The bounded result of the call.
        outcome: UpstreamObserveOutcome,
    },
    /// Resolution returned an answer.
    Completed {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The response code of the returned answer.
        rcode: Rcode,
    },
    /// Resolution returned an error classified without carrying its text.
    Failed {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
        /// The classified failure, without its underlying error text.
        failure: ObserveFailure,
    },
    /// Reserved for a future explicit cancellation boundary. Dropped resolve
    /// futures are not required to emit a terminal event in this stage.
    Cancelled {
        /// Opaque identifier correlating every event emitted for this query.
        correlation_id: u64,
    },
}

/// Bounded result of one optional route-hook call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookObserveDecision {
    /// The hook retained static routing.
    Abstain,
    /// The hook selected this group.
    Use(UpstreamGroupId),
    /// The hook returned an error.
    Failed,
}

/// Bounded outcome of one upstream call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamObserveOutcome {
    /// The backend returned an answer.
    Success,
    /// The backend failed and resolver failover continues.
    RetryableFailure,
    /// The backend failed and resolver returns immediately.
    Failure,
}

/// Bounded error classification used by [`ObserveEvent::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveFailure {
    /// No route, no question, unknown group, or empty group.
    NoRoute,
    /// The route hook failed.
    Hook,
    /// A transport timed out.
    Timeout,
    /// A transport operation failed.
    Transport,
    /// TLS setup or validation failed.
    Tls,
    /// Another resolver error occurred.
    Other,
}
