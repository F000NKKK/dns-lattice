//! A zone/domain matcher with deterministic exact/suffix/wildcard
//! precedence.
//!
//! # Precedence
//!
//! Matching is case-insensitive. An exact rule beats every suffix and
//! wildcard rule. Between suffix rules, or between wildcard rules, the rule
//! with the most labels wins. Equal kind and label-count ties retain
//! insertion order: the first inserted rule wins.
//!
//! ```
//! use dns_lattice_model::{DomainMatcher, DomainPattern, Name};
//!
//! let mut matcher = DomainMatcher::new();
//! matcher.insert(DomainPattern::wildcard(Name::from_ascii("example.com")?), "wildcard");
//! matcher.insert(DomainPattern::suffix(Name::from_ascii("example.com")?), "suffix");
//! matcher.insert(DomainPattern::suffix(Name::from_ascii("api.example.com")?), "specific suffix");
//! matcher.insert(DomainPattern::exact(Name::from_ascii("api.example.com")?), "exact");
//!
//! assert_eq!(matcher.resolve(&Name::from_ascii("API.EXAMPLE.COM")?), Some(&"exact"));
//! assert_eq!(matcher.resolve(&Name::from_ascii("v1.api.example.com")?), Some(&"specific suffix"));
//! # Ok::<(), dns_lattice_core::Error>(())
//! ```

use dns_lattice_core::{Error, Result};

use super::message::Name;

/// A single domain-matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    /// Matches only this exact name (case-insensitive).
    Exact(Name),
    /// Matches this name and any subdomain (e.g. `example.com` matches
    /// `example.com` and `foo.example.com`, not `notexample.com`).
    Suffix(Name),
    /// Matches subdomains of this name only (e.g. `*.example.com` matches
    /// `foo.example.com`, not `example.com` itself). Only a single leading
    /// `*` label is supported.
    Wildcard(Name),
}

impl DomainPattern {
    /// Constructs an exact-match pattern.
    pub fn exact(name: Name) -> Self {
        DomainPattern::Exact(name)
    }

    /// Constructs a suffix-match pattern.
    pub fn suffix(name: Name) -> Self {
        DomainPattern::Suffix(name)
    }

    /// Constructs a wildcard-match pattern.
    pub fn wildcard(name: Name) -> Self {
        DomainPattern::Wildcard(name)
    }

    /// Parses a pattern from its presentation form: a leading `"*."`
    /// produces a [`Wildcard`](DomainPattern::Wildcard) pattern over the
    /// remainder; any other `*` is rejected as
    /// [`Error::WildcardPosition`]; anything else produces a
    /// [`Suffix`](DomainPattern::Suffix) pattern.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("*.") {
            if rest.contains('*') {
                return Err(Error::WildcardPosition);
            }
            return Ok(DomainPattern::Wildcard(Name::from_ascii(rest)?));
        }
        if s.contains('*') {
            return Err(Error::WildcardPosition);
        }
        Ok(DomainPattern::Suffix(Name::from_ascii(s)?))
    }

    /// Whether `candidate` matches this pattern.
    pub fn matches(&self, candidate: &Name) -> bool {
        match self {
            DomainPattern::Exact(name) => candidate == name,
            DomainPattern::Suffix(name) => candidate.ends_with(name),
            DomainPattern::Wildcard(name) => {
                candidate.label_count() > name.label_count() && candidate.ends_with(name)
            }
        }
    }

    /// `(kind rank, matched-name label count)`, compared lexicographically:
    /// exact (2) beats suffix (1) beats wildcard (0); within a kind, more
    /// labels is more specific.
    fn specificity(&self) -> (u8, usize) {
        match self {
            DomainPattern::Exact(name) => (2, name.label_count()),
            DomainPattern::Suffix(name) => (1, name.label_count()),
            DomainPattern::Wildcard(name) => (0, name.label_count()),
        }
    }
}

/// A precedence-ordered collection of domain patterns mapped to a payload
/// `T`. Matching is case-insensitive and precedence is:
///
/// 1. Exact beats suffix beats wildcard beats no match.
/// 2. Within the same kind, a longer (more specific) match wins.
/// 3. A tie at equal kind and specificity is broken by insertion order:
///    the first-inserted rule wins.
#[derive(Debug, Clone)]
pub struct DomainMatcher<T> {
    rules: Vec<(DomainPattern, T)>,
}

impl<T> DomainMatcher<T> {
    /// Creates an empty matcher.
    pub fn new() -> Self {
        DomainMatcher { rules: Vec::new() }
    }

    /// Adds a rule. Later calls with an equally specific, equally kinded
    /// pattern lose ties to earlier ones.
    pub fn insert(&mut self, pattern: DomainPattern, value: T) {
        self.rules.push((pattern, value));
    }

    /// Returns the highest-precedence matching rule's value, or `None` if
    /// no rule matches.
    pub fn resolve(&self, name: &Name) -> Option<&T> {
        let mut best: Option<((u8, usize), &T)> = None;
        for (pattern, value) in &self.rules {
            if !pattern.matches(name) {
                continue;
            }
            let score = pattern.specificity();
            match best {
                Some((best_score, _)) if score <= best_score => {}
                _ => best = Some((score, value)),
            }
        }
        best.map(|(_, value)| value)
    }

    /// Returns every matching rule's value, in precedence order, for
    /// diagnostics and tests.
    pub fn resolve_all(&self, name: &Name) -> Vec<&T> {
        let mut matches: Vec<((u8, usize), &T)> = self
            .rules
            .iter()
            .filter(|(pattern, _)| pattern.matches(name))
            .map(|(pattern, value)| (pattern.specificity(), value))
            .collect();
        matches.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        matches.into_iter().map(|(_, value)| value).collect()
    }
}

impl<T> Default for DomainMatcher<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn exact_beats_suffix_beats_wildcard() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::wildcard(n("example.com")), "wildcard");
        m.insert(DomainPattern::suffix(n("example.com")), "suffix");
        m.insert(DomainPattern::exact(n("foo.example.com")), "exact");
        assert_eq!(m.resolve(&n("foo.example.com")), Some(&"exact"));
    }

    #[test]
    fn suffix_beats_wildcard_without_exact() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::wildcard(n("example.com")), "wildcard");
        m.insert(DomainPattern::suffix(n("example.com")), "suffix");
        assert_eq!(m.resolve(&n("foo.example.com")), Some(&"suffix"));
    }

    #[test]
    fn suffix_matches_its_own_apex() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::suffix(n("example.com")), "suffix");
        assert_eq!(m.resolve(&n("example.com")), Some(&"suffix"));
    }

    #[test]
    fn wildcard_does_not_match_its_own_apex() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::wildcard(n("example.com")), "wildcard");
        assert_eq!(m.resolve(&n("example.com")), None);
    }

    #[test]
    fn wildcard_matches_strict_subdomain() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::wildcard(n("example.com")), "wildcard");
        assert_eq!(m.resolve(&n("foo.example.com")), Some(&"wildcard"));
    }

    #[test]
    fn longer_suffix_wins_over_shorter() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::suffix(n("example.com")), "short");
        m.insert(DomainPattern::suffix(n("foo.example.com")), "long");
        assert_eq!(m.resolve(&n("bar.foo.example.com")), Some(&"long"));
    }

    #[test]
    fn tie_is_broken_by_insertion_order() {
        let mut first_wins = DomainMatcher::new();
        first_wins.insert(DomainPattern::suffix(n("example.com")), "a");
        first_wins.insert(DomainPattern::suffix(n("example.com")), "b");
        assert_eq!(first_wins.resolve(&n("example.com")), Some(&"a"));

        let mut order_flipped = DomainMatcher::new();
        order_flipped.insert(DomainPattern::suffix(n("example.com")), "b");
        order_flipped.insert(DomainPattern::suffix(n("example.com")), "a");
        assert_eq!(order_flipped.resolve(&n("example.com")), Some(&"b"));
    }

    #[test]
    fn no_match_returns_none() {
        let mut m: DomainMatcher<&str> = DomainMatcher::new();
        m.insert(DomainPattern::suffix(n("example.com")), "suffix");
        assert_eq!(m.resolve(&n("example.org")), None);
    }

    #[test]
    fn root_suffix_is_a_catch_all() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::suffix(Name::root()), "default");
        m.insert(DomainPattern::suffix(n("example.com")), "specific");
        assert_eq!(m.resolve(&n("anything.at.all")), Some(&"default"));
        assert_eq!(m.resolve(&n("foo.example.com")), Some(&"specific"));
    }

    #[test]
    fn parse_rejects_wildcard_not_in_leftmost_position() {
        assert_eq!(
            DomainPattern::parse("foo.*.example.com").unwrap_err(),
            Error::WildcardPosition
        );
        assert_eq!(
            DomainPattern::parse("*.*.example.com").unwrap_err(),
            Error::WildcardPosition
        );
    }

    #[test]
    fn parse_produces_wildcard_and_suffix() {
        assert_eq!(
            DomainPattern::parse("*.example.com").unwrap(),
            DomainPattern::wildcard(n("example.com"))
        );
        assert_eq!(
            DomainPattern::parse("example.com").unwrap(),
            DomainPattern::suffix(n("example.com"))
        );
    }

    #[test]
    fn matching_is_case_insensitive() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::suffix(n("EXAMPLE.com")), "suffix");
        assert_eq!(m.resolve(&n("foo.example.COM")), Some(&"suffix"));
    }

    #[test]
    fn resolve_all_orders_by_precedence() {
        let mut m = DomainMatcher::new();
        m.insert(DomainPattern::wildcard(n("example.com")), "wildcard");
        m.insert(DomainPattern::suffix(n("example.com")), "suffix");
        m.insert(DomainPattern::exact(n("foo.example.com")), "exact");
        assert_eq!(
            m.resolve_all(&n("foo.example.com")),
            vec![&"exact", &"suffix", &"wildcard"]
        );
    }
}
