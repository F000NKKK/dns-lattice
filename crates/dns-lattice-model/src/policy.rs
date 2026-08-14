//! Split-DNS policy types built on the [`matcher`](super::matcher) module.

use super::matcher::{DomainMatcher, DomainPattern};
use super::message::Name;

/// An opaque identifier for an upstream group.
///
/// The resolver/upstream layer owns what a group actually contains; the
/// model only needs something hashable and comparable to route to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamGroupId(String);

impl UpstreamGroupId {
    /// Creates a new upstream group identifier.
    pub fn new(id: impl Into<String>) -> Self {
        UpstreamGroupId(id.into())
    }

    /// Returns this identifier's string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A static split-DNS policy: which upstream group answers a query for a
/// given name.
#[derive(Debug, Clone)]
pub struct SplitDnsPolicy {
    matcher: DomainMatcher<UpstreamGroupId>,
    default_group: Option<UpstreamGroupId>,
}

impl SplitDnsPolicy {
    /// Starts building a policy.
    pub fn builder() -> SplitDnsPolicyBuilder {
        SplitDnsPolicyBuilder::default()
    }

    /// Resolves the upstream group that should answer a query for `name`,
    /// falling back to the default group (if any) when no rule matches.
    pub fn resolve_group(&self, name: &Name) -> Option<&UpstreamGroupId> {
        self.matcher.resolve(name).or(self.default_group.as_ref())
    }
}

/// Builds a [`SplitDnsPolicy`] from an ordered set of matching rules.
#[derive(Debug, Default)]
pub struct SplitDnsPolicyBuilder {
    matcher: DomainMatcher<UpstreamGroupId>,
    default_group: Option<UpstreamGroupId>,
}

impl SplitDnsPolicyBuilder {
    /// Adds a routing rule. Rules added earlier win ties, per
    /// [`DomainMatcher`]'s precedence rules.
    pub fn rule(mut self, pattern: DomainPattern, group: UpstreamGroupId) -> Self {
        self.matcher.insert(pattern, group);
        self
    }

    /// Sets the group used when no rule matches a query.
    pub fn default_group(mut self, group: UpstreamGroupId) -> Self {
        self.default_group = Some(group);
        self
    }

    /// Builds the policy.
    pub fn build(self) -> SplitDnsPolicy {
        SplitDnsPolicy {
            matcher: self.matcher,
            default_group: self.default_group,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn resolves_matching_group() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .build();
        assert_eq!(
            policy.resolve_group(&n("host.corp.internal")),
            Some(&UpstreamGroupId::new("corp"))
        );
    }

    #[test]
    fn falls_back_to_default_group_when_nothing_matches() {
        let policy = SplitDnsPolicy::builder()
            .rule(
                DomainPattern::suffix(n("corp.internal")),
                UpstreamGroupId::new("corp"),
            )
            .default_group(UpstreamGroupId::new("public"))
            .build();
        assert_eq!(
            policy.resolve_group(&n("example.com")),
            Some(&UpstreamGroupId::new("public"))
        );
    }

    #[test]
    fn no_match_and_no_default_returns_none() {
        let policy = SplitDnsPolicy::builder().build();
        assert_eq!(policy.resolve_group(&n("example.com")), None);
    }
}
