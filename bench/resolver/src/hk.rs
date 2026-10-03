//! The hickory contestant.
//!
//! One `TokioResolver` with a single name server, queried through
//! `Resolver::lookup`. Fairness settings, matching [`crate::dl`]:
//!
//! - **one attempt**: [`ONE_ATTEMPT`]. hickory's `attempts` counts retries,
//!   not tries, so `0` sends the query exactly once (a test confirms this
//!   against a responder that drops everything);
//! - `timeout` equal to the dns-lattice per-query timeout (default 2 s);
//! - `edns0` with a 1232-byte payload;
//! - `max_active_requests = 256`, at least the highest concurrency, so
//!   hickory's default of 32 per multiplexed connection never produces
//!   busy errors;
//! - `num_concurrent_reqs = 1`, `try_tcp_on_error = false`,
//!   `case_randomization = false`, the hosts file disabled, and no system
//!   configuration is read;
//! - the TLS configuration from [`crate::fixture::client_config`], handed
//!   over unchanged (hickory fills in ALPN per protocol when it is empty);
//! - the default 8,192-entry answer cache.
//!
//! hickory pools and multiplexes its connections, as dns-lattice now does on
//! TCP, DoT and DoH over HTTP/2; dns-lattice still opens a connection per
//! query on DoH3 and DoQ. The responder's connection counters show it.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
    ServerOrderingStrategy,
};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::Proto;
use crate::dl::Connect;
use crate::fixture::{self, SERVER_NAME};
use crate::loadgen::{Contestant, Outcome};
use crate::wire::{self, Mix};

/// The `ResolverOpts::attempts` value that makes hickory send each query
/// exactly once: it is the number of *retries* after the first try.
pub const ONE_ATTEMPT: usize = 0;
/// `ResolverOpts::max_active_requests`: at least the highest benchmark
/// concurrency.
pub const MAX_ACTIVE_REQUESTS: usize = 256;

/// A query prepared once per name.
pub struct Prepared {
    name: Name,
    rtype: RecordType,
    mix: Mix,
}

/// A hickory `TokioResolver` with one name server.
pub struct HkContestant {
    resolver: TokioResolver,
}

/// The resolver options both sides of the comparison use.
pub fn options(timeout: std::time::Duration) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.attempts = ONE_ATTEMPT;
    opts.timeout = timeout;
    opts.edns0 = true;
    opts.edns_payload_len = wire::EDNS_PAYLOAD;
    opts.num_concurrent_reqs = 1;
    opts.max_active_requests = MAX_ACTIVE_REQUESTS;
    opts.try_tcp_on_error = false;
    opts.case_randomization = false;
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    opts.use_hosts_file = ResolveHosts::Never;
    opts
}

impl HkContestant {
    /// Builds the contestant for `connect`.
    ///
    /// # Errors
    ///
    /// Returns a message if the TLS configuration or the resolver is
    /// invalid.
    pub fn new(connect: &Connect) -> Result<Self, String> {
        Self::with_options(connect, |_| {})
    }

    /// Like [`new`](Self::new), after `tweak` has adjusted the options; the
    /// tests use it to compare `attempts` and `max_active_requests`.
    ///
    /// # Errors
    ///
    /// Returns a message if the TLS configuration or the resolver is
    /// invalid.
    pub fn with_options(
        connect: &Connect,
        tweak: impl FnOnce(&mut ResolverOpts),
    ) -> Result<Self, String> {
        let name: Arc<str> = Arc::from(SERVER_NAME);
        let mut connection = match connect.proto {
            Proto::Udp => ConnectionConfig::udp(),
            Proto::Tcp => ConnectionConfig::tcp(),
            Proto::Dot => ConnectionConfig::tls(name),
            Proto::Doh2 => ConnectionConfig::https(name, None),
            Proto::Doh3 => ConnectionConfig::h3(name, None),
            Proto::Doq => ConnectionConfig::quic(name),
        };
        connection.port = connect.port;
        let server = NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, vec![connection]);
        let tls = fixture::client_config(&connect.ca_der).map_err(|e| e.to_string())?;
        let mut opts = options(connect.timeout);
        tweak(&mut opts);
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(vec![server]),
            TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .with_tls_config(tls)
        .build()
        .map_err(|e| format!("hickory resolver: {e}"))?;
        Ok(Self { resolver })
    }

    /// The underlying resolver.
    pub fn resolver(&self) -> &TokioResolver {
        &self.resolver
    }
}

impl Contestant for HkContestant {
    type Prepared = Prepared;

    fn prepare(&self, fqdn: &str, mix: Mix) -> Prepared {
        Prepared {
            name: Name::from_ascii(fqdn).expect("harness names are valid"),
            rtype: match mix {
                Mix::A | Mix::Nx => RecordType::A,
                Mix::Aaaa => RecordType::AAAA,
                Mix::Txt => RecordType::TXT,
            },
            mix,
        }
    }

    async fn query(&self, prepared: &Prepared) -> Outcome {
        match self
            .resolver
            .lookup(prepared.name.clone(), prepared.rtype)
            .await
        {
            Ok(lookup) => {
                let answers = lookup.answers();
                let matches = match prepared.mix {
                    Mix::A => matches!(answers, [one] if matches!(one.data, RData::A(_))),
                    Mix::Aaaa => matches!(answers, [one] if matches!(one.data, RData::AAAA(_))),
                    Mix::Txt => matches!(
                        answers,
                        [one] if matches!(&one.data, RData::TXT(txt) if txt.txt_data.len() == wire::TXT_STRINGS)
                    ),
                    Mix::Nx => false,
                };
                if matches {
                    Outcome::Ok
                } else {
                    Outcome::Mismatch
                }
            }
            Err(err) if err.is_nx_domain() => {
                if prepared.mix == Mix::Nx {
                    Outcome::Ok
                } else {
                    Outcome::Mismatch
                }
            }
            Err(NetError::Timeout) => Outcome::Timeout,
            Err(NetError::Busy) => Outcome::Error("busy"),
            Err(NetError::NoConnections) => Outcome::Error("no-connections"),
            Err(NetError::Msg(msg)) if msg.contains("channel is full") => {
                Outcome::Error("channel-full")
            }
            Err(_) => Outcome::Error("other"),
        }
    }
}
