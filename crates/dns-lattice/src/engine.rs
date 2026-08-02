//! In-process resolver entry point: construct-from-config, resolve one
//! query, and route it via static split-DNS matching (stage 0.1's
//! [`SplitDnsPolicy`]) to an upstream group.
//!
//! Stage 0.2 delivers routing only — no answer cache and no real network
//! transport yet (see `ARCHITECTURE.md`'s stage sequencing). The upstream
//! backend seam (`UpstreamBackend`) is crate-private and intentionally
//! minimal; it is not a preview of the stage 0.3 public `upstream` trait.

use std::collections::HashMap;

use dns_lattice_core::{Error, Result};
use dns_lattice_model::{Message, SplitDnsPolicy, UpstreamGroupId};

/// A synchronous, single-query seam between "which upstream group did
/// routing select" and "get an answer [`Message`] back".
///
/// Crate-private per ADR-0009: stage 0.2 resolves exactly one backend per
/// [`UpstreamGroupId`], with no failover across multiple backends within a
/// group. Stage 0.3 designs its own public `upstream` trait independently.
pub(crate) trait UpstreamBackend {
    /// Resolves `query` against this backend, returning the answer message
    /// or an error if the backend itself fails.
    fn resolve(&self, query: &Message) -> Result<Message>;
}

// Any `Fn(&Message) -> Result<Message>` is usable as an [`UpstreamBackend`],
// so [`ResolverBuilder::backend`] can accept a plain closure without ever
// naming the crate-private trait in its own (public) signature.
impl<F> UpstreamBackend for F
where
    F: Fn(&Message) -> Result<Message>,
{
    fn resolve(&self, query: &Message) -> Result<Message> {
        self(query)
    }
}

/// An in-process DNS resolver: construct from a split-DNS policy and one
/// upstream backend per group, then resolve queries against it.
///
/// # Lifecycle
///
/// Construct via [`Resolver::builder`], call [`Resolver::resolve`] as many
/// times as needed, then drop. This stage holds no background threads or
/// sockets, so there is no explicit `shutdown` method — Rust's ordinary drop
/// semantics fully release any resources the resolver owns.
pub struct Resolver {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Box<dyn UpstreamBackend + Send + Sync>>,
}

impl Resolver {
    /// Starts building a resolver from a split-DNS policy.
    pub fn builder(policy: SplitDnsPolicy) -> ResolverBuilder {
        ResolverBuilder {
            policy,
            backends: HashMap::new(),
        }
    }

    /// Resolves one query.
    ///
    /// Extracts the queried name from `query`'s first question, routes it
    /// through the configured [`SplitDnsPolicy`] to select an upstream
    /// group, and forwards the query to that group's backend.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoRoute`] when no split-DNS rule matches the
    /// queried name and no default upstream group is configured, or when no
    /// question is present in `query`. Returns whatever error the selected
    /// backend produces, propagated as-is.
    pub fn resolve(&self, query: &Message) -> Result<Message> {
        let question = query.questions.first().ok_or(Error::NoRoute)?;
        let group = self
            .policy
            .resolve_group(&question.name)
            .ok_or(Error::NoRoute)?;
        let backend = self.backends.get(group).ok_or(Error::NoRoute)?;
        backend.resolve(query)
    }
}

/// Builds a [`Resolver`] from a split-DNS policy and one upstream backend
/// per group.
pub struct ResolverBuilder {
    policy: SplitDnsPolicy,
    backends: HashMap<UpstreamGroupId, Box<dyn UpstreamBackend + Send + Sync>>,
}

impl ResolverBuilder {
    /// Registers the upstream backend used to answer queries routed to
    /// `group`. A later call for the same `group` replaces the earlier
    /// registration.
    ///
    /// `backend` is a plain function/closure from a query [`Message`] to a
    /// resolved answer [`Message`]; stage 0.2 has no real transport, so this
    /// is how a fake in-process backend is wired in for testing.
    pub fn backend(
        mut self,
        group: UpstreamGroupId,
        backend: impl Fn(&Message) -> Result<Message> + Send + Sync + 'static,
    ) -> Self {
        self.backends.insert(group, Box::new(backend));
        self
    }

    /// Builds the resolver.
    pub fn build(self) -> Resolver {
        Resolver {
            policy: self.policy,
            backends: self.backends,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_lattice_model::{
        Class, DomainPattern, Header, Name, Opcode, Question, Rcode, RecordType,
    };

    /// A minimal test-only backend closure factory: always returns a fixed
    /// answer, proving wiring without modelling any real upstream behavior.
    fn fixed_backend(
        answer: Message,
    ) -> impl Fn(&Message) -> Result<Message> + Send + Sync + 'static {
        move |_query: &Message| Ok(answer.clone())
    }

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn query_for(name: &str) -> Message {
        Message {
            header: Header {
                id: 1,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: n(name),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn answer_tagged(id: u16) -> Message {
        let mut msg = query_for("tag.example");
        msg.header.id = id;
        msg.header.qr = true;
        msg
    }

    #[test]
    fn routes_exact_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::exact(n("host.corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(42)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect("routed to corp backend");
        assert_eq!(answer.header.id, 42);
    }

    #[test]
    fn routes_suffix_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(7)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect("routed to corp backend via suffix");
        assert_eq!(answer.header.id, 7);
    }

    #[test]
    fn routes_wildcard_match_to_its_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::wildcard(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("corp"),
                fixed_backend(answer_tagged(9)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect("routed to corp backend via wildcard");
        assert_eq!(answer.header.id, 9);
    }

    #[test]
    fn routes_unmatched_query_to_default_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .default_group(UpstreamGroupId::new("public"))
            .build();
        let resolver = Resolver::builder(policy)
            .backend(
                UpstreamGroupId::new("public"),
                fixed_backend(answer_tagged(3)),
            )
            .build();

        let answer = resolver
            .resolve(&query_for("example.com"))
            .expect("routed to default group");
        assert_eq!(answer.header.id, 3);
    }

    #[test]
    fn no_route_when_no_match_and_no_default_group() {
        let policy = SplitDnsPolicy::builder().build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("example.com"))
            .expect_err("no rule and no default group configured");
        assert_eq!(err, Error::NoRoute);
    }

    #[test]
    fn no_route_when_matched_group_has_no_registered_backend() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy).build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect_err("matched group has no backend registered");
        assert_eq!(err, Error::NoRoute);
    }

    #[test]
    fn backend_error_propagates_as_is() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        let resolver = Resolver::builder(policy)
            .backend(UpstreamGroupId::new("corp"), |_query: &Message| {
                Err(Error::NameTooLong)
            })
            .build();

        let err = resolver
            .resolve(&query_for("host.corp.internal"))
            .expect_err("backend failure propagates");
        assert_eq!(err, Error::NameTooLong);
    }
}
