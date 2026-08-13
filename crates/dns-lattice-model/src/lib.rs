//! The DNS message, zone/domain matcher, and policy model for DNS Lattice.
//!
//! The facade crate exposes these types canonically through
//! `dns_lattice::model`; direct users of this crate can use its `message`,
//! `matcher`, `policy`, and `record` modules. Root-level re-exports remain
//! available for convenience.
//!
//! No network I/O, no operating-system dependency — see `ARCHITECTURE.md`
//! for the crate's non-goals at this stage.

pub mod matcher;
pub mod message;
pub mod policy;
pub mod record;

pub use matcher::{DomainMatcher, DomainPattern};
pub use message::{Header, Message, Name, Opcode, Question, Rcode, ResourceRecord};
pub use policy::{SplitDnsPolicy, SplitDnsPolicyBuilder, UpstreamGroupId};
pub use record::{Class, RData, RecordType};
