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
//!     core::Result,
//!     engine::Resolver,
//!     model::{SplitDnsPolicy, UpstreamGroupId},
//!     server::ServerBuilder,
//!     upstream::{UdpBackend, UdpBackendConfig},
//! };
//!
//! # async fn run() -> Result<()> {
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
//! # Dynamic routing hooks
//!
//! [`hooks::RouteHook`] is an opt-in, selection-only extension point for an
//! ordinary query. The resolver first obtains the static split-DNS candidate,
//! then invokes one configured hook, validates the resulting group, looks in
//! that group's cache scope, and finally tries that group's upstreams in
//! order. A local Fake IP answer is terminal before this sequence.
//!
//! This in-process example installs a hook and an in-process backend; it
//! opens no socket. Add `async-trait` to an application's dependencies when
//! implementing [`hooks::RouteHook`].
//!
//! ```no_run
//! use async_trait::async_trait;
//! use dns_lattice::{
//!     core::Result,
//!     engine::Resolver,
//!     hooks::{RouteDecision, RouteHook, RouteHookError, RouteRequest},
//!     model::{Message, SplitDnsPolicy, UpstreamGroupId},
//!     upstream::UpstreamBackend,
//! };
//!
//! struct PreferFiltered;
//!
//! #[async_trait]
//! impl RouteHook for PreferFiltered {
//!     async fn select(
//!         &self,
//!         request: RouteRequest<'_>,
//!     ) -> std::result::Result<RouteDecision, RouteHookError> {
//!         let _question = request.question();
//!         let _static_candidate = request.static_group();
//!         Ok(RouteDecision::Use(UpstreamGroupId::new("filtered")))
//!     }
//! }
//!
//! struct InProcessBackend;
//!
//! #[async_trait]
//! impl UpstreamBackend for InProcessBackend {
//!     async fn resolve(&self, query: &Message) -> Result<Message> {
//!         Ok(query.clone())
//!     }
//! }
//!
//! let resolver = Resolver::builder(SplitDnsPolicy::builder().build())
//!     .backend(UpstreamGroupId::new("filtered"), InProcessBackend)
//!     .route_hook(PreferFiltered)
//!     .build();
//! # let _ = resolver;
//! ```
//!
//! A hook error, an unknown selected group, or an empty selected group is a
//! resolver error: it never falls back to static routing, touches the cache,
//! or calls an upstream. Cache entries are scoped by the validated effective
//! group, so equal DNS questions selected to different groups cannot share an
//! answer. The hook implementation owns timeout, retry, and cancellation
//! cleanup; dropping [`engine::Resolver::resolve`] drops its in-flight hook
//! future. A hook must not re-enter the same resolver directly or indirectly.
//! Hooks receive neither resolver/backend handles nor client metadata, and
//! DNS Lattice gives them no OS or networking side-effect capability; a host
//! application composes such work outside this crate.
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
//! There are no flat root aliases. Use the domain-scoped module paths above,
//! which make ownership and responsibility explicit.
//!
//! Each legacy root import is intentionally rejected. These compile-fail
//! examples are checked in every supported feature documentation build; the
//! encrypted transport checks therefore also run with all transport features.
//!
//! ```compile_fail
//! use dns_lattice::Error;
//! ```
//! ```compile_fail
//! use dns_lattice::Result;
//! ```
//! ```compile_fail
//! use dns_lattice::Name;
//! ```
//! ```compile_fail
//! use dns_lattice::Class;
//! ```
//! ```compile_fail
//! use dns_lattice::Message;
//! ```
//! ```compile_fail
//! use dns_lattice::Header;
//! ```
//! ```compile_fail
//! use dns_lattice::Question;
//! ```
//! ```compile_fail
//! use dns_lattice::RData;
//! ```
//! ```compile_fail
//! use dns_lattice::ResourceRecord;
//! ```
//! ```compile_fail
//! use dns_lattice::RecordType;
//! ```
//! ```compile_fail
//! use dns_lattice::Rcode;
//! ```
//! ```compile_fail
//! use dns_lattice::Opcode;
//! ```
//! ```compile_fail
//! use dns_lattice::DomainMatcher;
//! ```
//! ```compile_fail
//! use dns_lattice::DomainPattern;
//! ```
//! ```compile_fail
//! use dns_lattice::SplitDnsPolicy;
//! ```
//! ```compile_fail
//! use dns_lattice::SplitDnsPolicyBuilder;
//! ```
//! ```compile_fail
//! use dns_lattice::UpstreamGroupId;
//! ```
//! ```compile_fail
//! use dns_lattice::Resolver;
//! ```
//! ```compile_fail
//! use dns_lattice::ResolverBuilder;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpPool;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpPoolBuilder;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpPoolSnapshot;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpPolicy;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpPolicyBuilder;
//! ```
//! ```compile_fail
//! use dns_lattice::FakeIpMappingSnapshot;
//! ```
//! ```compile_fail
//! use dns_lattice::Server;
//! ```
//! ```compile_fail
//! use dns_lattice::ServerBuilder;
//! ```
//! ```compile_fail
//! use dns_lattice::UpstreamBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::UdpBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::UdpBackendConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::TcpBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::TcpBackendConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::DotBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::DotBackendConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::DohBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::DohBackendConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::DohMethod;
//! ```
//! ```compile_fail
//! use dns_lattice::Doh3Backend;
//! ```
//! ```compile_fail
//! use dns_lattice::Doh3BackendConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::DohListenerConfig;
//! ```
//! ```compile_fail
//! use dns_lattice::DoqBackend;
//! ```
//! ```compile_fail
//! use dns_lattice::DoqBackendConfig;
//! ```

pub mod engine;
pub mod fakeip;
/// Shared error and result types.
///
/// This is the canonical facade path for [`dns_lattice_core::Error`] and
/// [`dns_lattice_core::Result`], supplied by `dns-lattice-core`.
pub mod core {
    pub use dns_lattice_core::{Error, Result};
}
/// Caller-supplied dynamic upstream-group selection types.
///
/// This is the canonical facade path for [`hooks::RouteHook`] and its
/// request, decision, and error types. Route hooks are intentionally not
/// re-exported from the crate root.
pub mod hooks;
/// Optional, non-authoritative resolver event sink.
pub mod observability;
/// DNS message, domain-matching, and split-DNS policy types.
///
/// This is the canonical facade path for types supplied by
/// `dns-lattice-model`; for example, import [`dns_lattice_model::Name`] as
/// `dns_lattice::model::Name`.
pub mod model {
    pub use dns_lattice_model::{
        Class, DomainMatcher, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode,
        RecordType, ResourceRecord, SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId,
    };
}
pub mod server;
pub mod upstream;

#[cfg(test)]
mod facade_path_tests {
    use super::{core, engine, fakeip, hooks, model, server, upstream};

    #[test]
    fn canonical_module_paths_expose_the_public_surface() {
        let _: model::Name = model::Name::root();
        let _: Option<model::DomainMatcher<()>> = Some(model::DomainMatcher::new());
        let _: fn(model::Name) -> model::DomainPattern = model::DomainPattern::suffix;
        let _: fn(model::SplitDnsPolicy) -> engine::ResolverBuilder = engine::Resolver::builder;

        let _: Option<hooks::RouteDecision> = Some(hooks::RouteDecision::Abstain);
        let _: Option<&dyn hooks::RouteHook> = None;
        let _: Option<fakeip::FakeIpPool> = None;
        let _: Option<server::Server> = None;
        let _: Option<upstream::UdpBackend> = None;
        let _: Option<core::Error> = None;
        let _: Option<core::Result<()>> = None;
    }
}
