//! Programmable Rust DNS control plane for the Lattice networking stack:
//! split DNS, Fake IP, address pools, and dynamic routing hooks.
//!
//! # Canonical module imports
//!
//! ```
//! use dns_lattice::model::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};
//!
//! let policy = SplitDnsPolicy::builder()
//!     .rule(
//!         DomainPattern::suffix(Name::from_ascii("corp.internal").unwrap()),
//!         UpstreamGroupId::new("corp"),
//!     )
//!     .build();
//!
//! let name = Name::from_ascii("host.corp.internal").unwrap();
//! assert_eq!(policy.resolve_group(&name), Some(&UpstreamGroupId::new("corp")));
//! ```
//!
//! # Facade design
//!
//! The canonical imports are domain-scoped: [`model`] for message, matcher,
//! and policy types; [`engine`] for query orchestration; [`upstream`] for
//! outbound transports; [`server`] for inbound listeners; and [`fakeip`] for
//! caller-invoked synthetic-address storage. `Error` and `Result` are shared
//! across those domains.
//!
//! Existing flat aliases such as [`Name`], [`Resolver`], and [`UdpBackend`]
//! remain supported for compatibility. New code should prefer the canonical
//! module paths above, which make ownership and responsibility explicit.

pub mod engine;
pub mod fakeip;
/// DNS message, domain-matching, and split-DNS policy types.
///
/// This is the canonical facade path for types supplied by
/// `dns-lattice-model`; for example, import [`Name`] as
/// `dns_lattice::model::Name`. The flat root aliases remain supported for
/// compatibility.
pub mod model {
    pub use dns_lattice_model::{
        Class, DomainMatcher, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode,
        RecordType, ResourceRecord, SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId,
    };
}
pub mod server;
pub mod upstream;

pub use dns_lattice_core::{Error, Result};
pub use engine::{Resolver, ResolverBuilder};
pub use fakeip::{FakeIpPolicy, FakeIpPolicyBuilder, FakeIpPool, FakeIpPoolBuilder};
pub use model::{
    Class, DomainMatcher, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode,
    RecordType, ResourceRecord, SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId,
};
pub use server::{Server, ServerBuilder};
#[cfg(feature = "doh")]
pub use upstream::{DohBackend, DohBackendConfig, DohMethod};
#[cfg(feature = "doq")]
pub use upstream::{DoqBackend, DoqBackendConfig};
#[cfg(feature = "dot")]
pub use upstream::{DotBackend, DotBackendConfig};
pub use upstream::{TcpBackend, TcpBackendConfig, UdpBackend, UdpBackendConfig, UpstreamBackend};

#[cfg(test)]
mod facade_path_tests {
    use super::{DomainMatcher, DomainPattern, Name, Resolver, ResolverBuilder, model};

    #[test]
    fn canonical_model_paths_and_flat_aliases_name_the_same_types() {
        let _: model::Name = Name::root();
        let _: Option<model::DomainMatcher<()>> = Some(DomainMatcher::new());
        let _: fn(model::Name) -> model::DomainPattern = DomainPattern::suffix;
        let _: fn(model::SplitDnsPolicy) -> ResolverBuilder = Resolver::builder;
    }
}
