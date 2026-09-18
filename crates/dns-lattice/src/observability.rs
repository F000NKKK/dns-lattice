//! Optional, non-authoritative resolver observability.
//!
//! [`ObservabilitySink`](crate::observability::ObservabilitySink) receives
//! immutable, synchronous [`ObserveEvent`](crate::observability::ObserveEvent)
//! values after each resolver transition. Sinks are advisory only: a panic is
//! isolated, and a sink cannot alter routing, caching, retries, or answers.
//! Events contain no client address, resolver/backend handle, or error text.

use crate::model::{Class, Name, Rcode, RecordType, UpstreamGroupId};

/// A synchronous, thread-safe observer for resolver events.
///
/// Implementations must not re-enter the same resolver. The resolver invokes
/// this callback without holding its cache lock; a callback panic is ignored.
pub trait ObservabilitySink: Send + Sync {
    /// Receives one immutable, ordered event.
    fn record(&self, event: &ObserveEvent);
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
