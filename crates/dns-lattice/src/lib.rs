//! Programmable Rust DNS control plane for the Lattice networking stack:
//! split DNS, Fake IP, address pools, and dynamic routing hooks.
//!
//! # Example
//!
//! ```
//! use dns_lattice::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};
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
//! Re-exports the DNS message, matcher, and policy types from
//! `dns-lattice-model`, and the shared `Error`/`Result` pair from
//! `dns-lattice-core`. Stage 0.1 implemented the `model` layer; stage 0.2
//! added the [`engine`] module's [`Resolver`] (construct/resolve, static
//! split-DNS routing, and an in-memory TTL/negative-caching answer cache).
//! Stage 0.3 adds the [`upstream`] module's public, async
//! [`UpstreamBackend`] trait plus baseline [`UdpBackend`]/[`TcpBackend`]
//! transport implementations, plus DNS-over-TLS/DNS-over-HTTPS/
//! DNS-over-QUIC backends behind the default-off `dot`/`doh`/`doq` Cargo
//! features, and the [`server`] module's [`Server`]/[`ServerBuilder`]
//! inbound UDP/TCP baseline plus DoT/DoQ listeners — the first slice
//! fulfilling the embeddable-DNS-server-engine goal (ADR-0015, `DL-A-16`;
//! DoT/DoQ per ADR-0016, `DL-A-17`). Later follow-up work adds `server`'s
//! DoH listener, plus `fakeip` and `hooks`, behind this same facade. See
//! `ARCHITECTURE.md` for the full module layout.

pub mod engine;
pub mod server;
pub mod upstream;

pub use dns_lattice_core::{Error, Result};
pub use dns_lattice_model::{
    Class, DomainMatcher, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode,
    RecordType, ResourceRecord, SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId,
};
pub use engine::{Resolver, ResolverBuilder};
pub use server::{Server, ServerBuilder};
#[cfg(feature = "doh")]
pub use upstream::{DohBackend, DohBackendConfig, DohMethod};
#[cfg(feature = "doq")]
pub use upstream::{DoqBackend, DoqBackendConfig};
#[cfg(feature = "dot")]
pub use upstream::{DotBackend, DotBackendConfig};
pub use upstream::{TcpBackend, TcpBackendConfig, UdpBackend, UdpBackendConfig, UpstreamBackend};
