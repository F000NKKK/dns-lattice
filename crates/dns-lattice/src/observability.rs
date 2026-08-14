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
        correlation_id: u64,
        name: Option<Name>,
        rtype: Option<RecordType>,
        class: Option<Class>,
    },
    /// Fake IP returned a terminal local answer.
    FakeIpTerminal { correlation_id: u64 },
    /// Static split-DNS selected a tentative group, if any.
    StaticRoute {
        correlation_id: u64,
        group: Option<UpstreamGroupId>,
    },
    /// The optional hook's selection-only decision.
    HookDecision {
        correlation_id: u64,
        decision: HookObserveDecision,
    },
    /// The route-scoped cache supplied an answer.
    CacheHit {
        correlation_id: u64,
        group: UpstreamGroupId,
    },
    /// The route-scoped cache did not supply an answer.
    CacheMiss {
        correlation_id: u64,
        group: UpstreamGroupId,
    },
    /// One backend is about to be called; its index is registration order.
    UpstreamAttempt {
        correlation_id: u64,
        group: UpstreamGroupId,
        backend_index: usize,
    },
    /// One backend completed without exposing an error string or handle.
    UpstreamOutcome {
        correlation_id: u64,
        group: UpstreamGroupId,
        backend_index: usize,
        outcome: UpstreamObserveOutcome,
    },
    /// Resolution returned an answer.
    Completed { correlation_id: u64, rcode: Rcode },
    /// Resolution returned an error classified without carrying its text.
    Failed {
        correlation_id: u64,
        failure: ObserveFailure,
    },
    /// Reserved for a future explicit cancellation boundary. Dropped resolve
    /// futures are not required to emit a terminal event in this stage.
    Cancelled { correlation_id: u64 },
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
