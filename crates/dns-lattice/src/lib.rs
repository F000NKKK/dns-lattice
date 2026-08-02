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
//! `dns-lattice-core`. Stage 0.1 only implements the `model` layer; later
//! stages add `server`, `engine`, `upstream`, `fakeip`, and `hooks` behind
//! this same facade. See `ARCHITECTURE.md` for the full module layout.

pub use dns_lattice_core::{Error, Result};
pub use dns_lattice_model::{
    Class, DomainMatcher, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode,
    RecordType, ResourceRecord, SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId,
};
