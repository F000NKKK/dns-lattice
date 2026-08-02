//! The DNS message, zone/domain matcher, and policy model for DNS Lattice.
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
