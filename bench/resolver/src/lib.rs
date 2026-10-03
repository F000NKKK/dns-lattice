//! Resolver benchmark harness for dns-lattice, measured next to hickory.
//!
//! This library holds the library-neutral pieces of the harness. Its wire
//! and responder code never parse DNS with either library under test, so
//! neither side's codec is part of the other side's measurement.
//!
//! - [`wire`]: hand-written DNS query parsing and deterministic response
//!   building, used by the upstream responder and as the identical input
//!   bytes of the codec micro-benchmarks.
//! - [`fixture`]: a throwaway CA and leaf certificate, and the one shared
//!   TLS client configuration both contestants use.
//! - [`responder`]: the loopback upstream (UDP, TCP, DoT, DoH over HTTP/2,
//!   DoH over HTTP/3 and DoQ) with a fixed reply latency and counters for
//!   queries, connections and TLS handshakes.
//! - [`loadgen`]: the closed-loop load generator that drives either
//!   contestant and records latencies.
//! - [`dl`] and [`hk`]: the two contestants behind one [`loadgen::Contestant`]
//!   interface, configured with the same fairness settings.
//! - [`metrics`]: process CPU and memory samples (Linux `/proc`).
//! - [`cli`]: the small hand-written command-line parser the binaries share.
//!
//! The criterion micro-benchmarks live in `benches/`; see `README.md`.

#![warn(missing_docs)]

pub mod cli;
pub mod dl;
pub mod fixture;
pub mod hk;
pub mod loadgen;
pub mod metrics;
pub mod responder;
pub mod wire;

use std::fmt;

/// A DNS transport the responder serves and the contestants query over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS over HTTP/2 (RFC 8484).
    Doh2,
    /// DNS over HTTPS over HTTP/3.
    Doh3,
    /// DNS over QUIC (RFC 9250).
    Doq,
}

impl Proto {
    /// Every transport, in a fixed order.
    pub const ALL: [Proto; 6] = [
        Proto::Udp,
        Proto::Tcp,
        Proto::Dot,
        Proto::Doh2,
        Proto::Doh3,
        Proto::Doq,
    ];

    /// The command-line and report name of this transport.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Dot => "dot",
            Proto::Doh2 => "doh2",
            Proto::Doh3 => "doh3",
            Proto::Doq => "doq",
        }
    }

    /// Parses a transport from its [`as_str`](Proto::as_str) name.
    pub fn parse(name: &str) -> Option<Proto> {
        Proto::ALL.into_iter().find(|proto| proto.as_str() == name)
    }

    /// The position of this transport in [`Proto::ALL`].
    pub fn index(self) -> usize {
        match self {
            Proto::Udp => 0,
            Proto::Tcp => 1,
            Proto::Dot => 2,
            Proto::Doh2 => 3,
            Proto::Doh3 => 4,
            Proto::Doq => 5,
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
