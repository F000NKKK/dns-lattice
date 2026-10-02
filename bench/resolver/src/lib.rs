//! Resolver benchmark harness for dns-lattice, measured next to hickory.
//!
//! This library holds the library-neutral pieces of the harness. It never
//! parses DNS with either library under test, so neither side's codec is
//! part of the other side's measurement.
//!
//! - [`wire`]: hand-written DNS query parsing and deterministic response
//!   building, used by the upstream responder and as the identical input
//!   bytes of the codec micro-benchmarks.
//!
//! The criterion micro-benchmarks live in `benches/`; see `README.md`.

#![warn(missing_docs)]

pub mod wire;
