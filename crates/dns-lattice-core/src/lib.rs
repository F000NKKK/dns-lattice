//! Foundational error and result types shared across the DNS Lattice
//! workspace.
//!
//! `dns-lattice-core` carries no networking-specific types and no
//! operating-system dependency — those belong to `dns-lattice` itself and
//! its future modules. See `ARCHITECTURE.md` for the full rationale.

mod error;

pub use error::Error;

/// A result returned by DNS Lattice operations.
pub type Result<T> = core::result::Result<T, Error>;
