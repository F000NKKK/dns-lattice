//! Programmable Rust DNS control plane for the Lattice networking stack:
//! split DNS, Fake IP, address pools, and dynamic routing hooks.
//!
//! # Quick start
//!
//! The usual inbound path is `Server` → `Resolver` → static split-DNS
//! policy → `UpstreamBackend`. This `no_run` example uses the baseline UDP
//! transport; it needs a Tokio runtime, an available local listen address,
//! and a reachable upstream to run.
//!
//! ```no_run
//! use std::{net::SocketAddr, sync::Arc, time::Duration};
//!
//! use dns_lattice::{
//!     engine::Resolver,
//!     model::{SplitDnsPolicy, UpstreamGroupId},
//!     server::ServerBuilder,
//!     upstream::{UdpBackend, UdpBackendConfig},
//! };
//!
//! # async fn run() -> dns_lattice::Result<()> {
//! let group = UpstreamGroupId::new("default");
//! let policy = SplitDnsPolicy::builder().default_group(group.clone()).build();
//! let resolver = Arc::new(
//!     Resolver::builder(policy)
//!         .backend(
//!             group,
//!             UdpBackend::new(UdpBackendConfig {
//!                 server: "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
//!                 timeout: Duration::from_secs(5),
//!                 bind_addr: None,
//!             }),
//!         )
//!         .build(),
//! );
//! let server = ServerBuilder::new(resolver)
//!     .udp_addr("127.0.0.1:5353".parse().unwrap())
//!     .bind()
//!     .await?;
//! server.serve().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Fake IP
//!
//! [`fakeip::FakeIpPool`] and [`fakeip::FakeIpPolicy`] are opt-in through
//! [`engine::ResolverBuilder::fake_ip`]. Matching IN A/AAAA and canonical,
//! in-range IN PTR questions receive local synthetic answers that bypass the
//! ordinary cache and upstreams. The emitted DNS TTL never exceeds the
//! mapping's remaining lifetime; pools remain caller-owned and have no
//! durable persistence built in.
//!
//! # Transport features
//!
//! UDP and TCP are available without Cargo features. The default-off `dot`,
//! `doh`, and `doq` features respectively add DNS-over-TLS,
//! DNS-over-HTTPS (including HTTP/3 over QUIC), and DNS-over-QUIC. `doh`
//! therefore includes HTTP/3/QUIC dependencies; `doq` remains an independent
//! feature for DNS-over-QUIC without the HTTP stack.
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
//! synthetic-address pools, policies, and snapshots. `Error` and `Result` are
//! shared across those domains. [`engine::ResolverBuilder::fake_ip`] explicitly
//! connects a pool and policy to local Fake IP DNS synthesis.
//!
//! Existing flat aliases such as [`Name`], [`Resolver`], and [`UdpBackend`]
//! remain supported for compatibility. New code should prefer the canonical
//! module paths above, which make ownership and responsibility explicit.

pub mod engine;
pub mod fakeip;
/// Caller-supplied dynamic upstream-group selection types.
///
/// This is the canonical facade path for [`hooks::RouteHook`] and its
/// request, decision, and error types. Route hooks are intentionally not
/// re-exported from the crate root.
pub mod hooks;
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
pub use fakeip::{
    FakeIpMappingSnapshot, FakeIpPolicy, FakeIpPolicyBuilder, FakeIpPool, FakeIpPoolBuilder,
    FakeIpPoolSnapshot,
};
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
    use super::{DomainMatcher, DomainPattern, Name, Resolver, ResolverBuilder, hooks, model};

    #[test]
    fn canonical_model_paths_and_flat_aliases_name_the_same_types() {
        let _: model::Name = Name::root();
        let _: Option<model::DomainMatcher<()>> = Some(DomainMatcher::new());
        let _: fn(model::Name) -> model::DomainPattern = DomainPattern::suffix;
        let _: fn(model::SplitDnsPolicy) -> ResolverBuilder = Resolver::builder;

        let _: Option<hooks::RouteDecision> = Some(hooks::RouteDecision::Abstain);
        let _: Option<&dyn hooks::RouteHook> = None;
    }
}
