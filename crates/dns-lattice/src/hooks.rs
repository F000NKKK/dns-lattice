//! Caller-supplied dynamic upstream-group selection.
//!
//! [`RouteHook`](crate::hooks::RouteHook) is a deliberately narrow extension point: it receives the
//! first DNS [`crate::model::Question`] and the upstream group tentatively selected by the
//! static split-DNS policy. It can authoritatively choose a registered group
//! with [`RouteDecision::Use`](crate::hooks::RouteDecision::Use) or preserve
//! the static candidate with
//! [`RouteDecision::Abstain`](crate::hooks::RouteDecision::Abstain).
//!
//! Hooks neither resolve DNS nor own cache, backend, Fake IP, server, or OS
//! networking state. In particular, they receive no client address, inbound
//! protocol, message header, response, mutable resolver, or backend handle.
//! An application that needs policy compilation or networking side effects
//! composes them outside DNS Lattice.
//!
//! A hook implementation owns its timeout, retry, and cancellation cleanup.
//! It must not call [`crate::engine::Resolver::resolve`] on the same resolver
//! directly or indirectly: same-resolver re-entrancy is unsupported.

use std::fmt;

use async_trait::async_trait;

use crate::model::{Question, UpstreamGroupId};

/// Asynchronously chooses an upstream group for one DNS question.
///
/// The resolver invokes at most one configured hook for a non-local query.
/// [`RouteDecision::Use`] overrides the tentative static group, while
/// [`RouteDecision::Abstain`] leaves it in effect. A failed hook is a routing
/// failure, not a request to fall back to static policy.
///
/// Implementors own any required timeout, retry, and cancellation cleanup.
/// They must not re-enter [`crate::engine::Resolver::resolve`] on the same
/// resolver, directly or indirectly.
#[async_trait]
pub trait RouteHook: Send + Sync {
    /// Selects a route for `request`.
    async fn select(
        &self,
        request: RouteRequest<'_>,
    ) -> std::result::Result<RouteDecision, RouteHookError>;
}

/// The information available to a [`RouteHook`] for one route-selection
/// decision.
///
/// Fields are private so a hook cannot gain access to resolver internals or
/// construct a request detached from the resolver's query pipeline.
pub struct RouteRequest<'a> {
    question: &'a Question,
    static_group: Option<&'a UpstreamGroupId>,
}

impl<'a> RouteRequest<'a> {
    // Constructed by Resolver's route-selection helper. The public contract
    // intentionally exposes accessors only; DL-93 declares the type before
    // the pipeline task wires that helper.
    #[allow(dead_code)]
    pub(crate) fn new(question: &'a Question, static_group: Option<&'a UpstreamGroupId>) -> Self {
        Self {
            question,
            static_group,
        }
    }

    /// Returns the first DNS question being routed.
    pub fn question(&self) -> &'a Question {
        self.question
    }

    /// Returns the upstream group tentatively selected by static split-DNS
    /// policy, if one exists.
    pub fn static_group(&self) -> Option<&'a UpstreamGroupId> {
        self.static_group
    }
}

/// A hook's route-selection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Authoritatively use this upstream group instead of the static
    /// split-DNS candidate.
    Use(UpstreamGroupId),
    /// Keep the static split-DNS candidate unchanged.
    Abstain,
}

/// A routing failure reported by a [`RouteHook`].
///
/// Resolver integration maps this error to the shared [`crate::core::Error::Hook`]
/// variant. It is not a request to fall back to static routing, retry an
/// upstream, or cache a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHookError {
    message: String,
}

impl RouteHookError {
    /// Creates a hook failure with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RouteHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RouteHookError {}

#[cfg(test)]
mod tests {
    use super::{RouteDecision, RouteHook, RouteHookError, RouteRequest};
    use crate::model::UpstreamGroupId;
    use async_trait::async_trait;

    struct AbstainingHook;

    #[async_trait]
    impl RouteHook for AbstainingHook {
        async fn select(
            &self,
            _request: RouteRequest<'_>,
        ) -> std::result::Result<RouteDecision, RouteHookError> {
            Ok(RouteDecision::Abstain)
        }
    }

    #[test]
    fn module_types_are_importable_and_route_hook_is_dyn_compatible() {
        fn accepts_dyn_hook(_: &dyn RouteHook) {}
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<AbstainingHook>();
        accepts_dyn_hook(&AbstainingHook);
        assert_eq!(
            RouteDecision::Use(UpstreamGroupId::new("alternate")),
            RouteDecision::Use(UpstreamGroupId::new("alternate"))
        );
    }

    #[test]
    fn hook_error_has_a_stable_display_message_and_implements_std_error() {
        let error = RouteHookError::new("policy service unavailable");
        assert_eq!(error.to_string(), "policy service unavailable");

        fn assert_std_error<E: std::error::Error>(_: &E) {}
        assert_std_error(&error);
    }
}
