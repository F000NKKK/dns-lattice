//! The dns-lattice contestant.
//!
//! One `Resolver` with a single backend in its default group, queried
//! through `Resolver::resolve`. Fairness settings:
//!
//! - one attempt and a timeout of [`Connect::timeout`] on every backend
//!   (dns-lattice never retries a single backend);
//! - EDNS(0) with a 1232-byte payload, added to every query as an OPT
//!   record so all transports carry it, like hickory's `edns0`;
//! - the TLS configuration from [`crate::fixture::client_config`], cloned
//!   per backend (DoQ gets ALPN `doq` set by the harness, as the backend
//!   requires; DoH and DoH3 set their own);
//! - the default answer cache.
//!
//! dns-lattice reuses connections on TCP, DoT, DoH over HTTP/2, DoH3 and DoQ
//! by default (a small pool; [`DlContestant::with_pool`] can switch it off).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use dns_lattice::core::Error;
use dns_lattice::engine::Resolver;
use dns_lattice::model::{
    Class, Edns, Header, Message, Name, Opcode, Question, RData, Rcode, RecordType, SplitDnsPolicy,
    UpstreamGroupId,
};
use dns_lattice::upstream::{
    Doh3Backend, Doh3BackendConfig, DohBackend, DohBackendConfig, DohMethod, DoqBackend,
    DoqBackendConfig, DotBackend, DotBackendConfig, PoolConfig, TcpBackend, TcpBackendConfig,
    UdpBackend, UdpBackendConfig,
};
use rustls::pki_types::ServerName;

use crate::Proto;
use crate::fixture::{self, SERVER_NAME};
use crate::loadgen::{Contestant, Outcome};
use crate::wire::{self, Mix};

/// Where and how a contestant reaches the responder.
#[derive(Debug, Clone)]
pub struct Connect {
    /// The transport to resolve over.
    pub proto: Proto,
    /// The responder's port for `proto` on `127.0.0.1`.
    pub port: u16,
    /// The fixture CA certificate (DER) to trust.
    pub ca_der: Vec<u8>,
    /// The per-query timeout, with exactly one attempt.
    pub timeout: std::time::Duration,
}

/// A query prepared once per name.
pub struct Prepared {
    name: Name,
    qtype: RecordType,
    mix: Mix,
}

/// A dns-lattice `Resolver` with one upstream backend.
pub struct DlContestant {
    resolver: Resolver,
    next_id: AtomicU16,
}

impl DlContestant {
    /// Builds the contestant for `connect`.
    ///
    /// # Errors
    ///
    /// Returns a message if the TLS configuration or a name is invalid.
    pub fn new(connect: &Connect) -> Result<Self, String> {
        Self::with_pool(connect, PoolConfig::new())
    }

    /// Builds the contestant for `connect` with an explicit connection-reuse
    /// policy for every pooled transport (UDP has none and ignores it).
    ///
    /// # Errors
    ///
    /// Returns a message if the TLS configuration or a name is invalid.
    pub fn with_pool(connect: &Connect, pool: PoolConfig) -> Result<Self, String> {
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, connect.port));
        let tls = Arc::new(fixture::client_config(&connect.ca_der).map_err(|e| e.to_string())?);
        let server_name =
            || ServerName::try_from(SERVER_NAME).map_err(|e| format!("server name: {e}"));
        let group = UpstreamGroupId::new("bench");
        let builder = Resolver::builder(
            SplitDnsPolicy::builder()
                .default_group(group.clone())
                .build(),
        );
        let resolver = match connect.proto {
            Proto::Udp => builder.backend(
                group,
                UdpBackend::new(UdpBackendConfig {
                    server,
                    timeout: connect.timeout,
                    bind_addr: None,
                }),
            ),
            Proto::Tcp => builder.backend(
                group,
                TcpBackend::new(TcpBackendConfig {
                    server,
                    connect_timeout: connect.timeout,
                    read_timeout: connect.timeout,
                })
                .with_pool(pool),
            ),
            Proto::Dot => builder.backend(
                group,
                DotBackend::new(DotBackendConfig {
                    server,
                    server_name: server_name()?,
                    tls_config: tls,
                    connect_timeout: connect.timeout,
                    read_timeout: connect.timeout,
                })
                .with_pool(pool),
            ),
            Proto::Doh2 => builder.backend(
                group,
                DohBackend::new(DohBackendConfig {
                    uri: format!("https://127.0.0.1:{}/dns-query", connect.port)
                        .parse()
                        .map_err(|e| format!("DoH uri: {e}"))?,
                    method: DohMethod::Post,
                    tls_config: tls,
                    timeout: connect.timeout,
                })
                .with_pool(pool),
            ),
            Proto::Doh3 => builder.backend(
                group,
                Doh3Backend::new(Doh3BackendConfig {
                    uri: format!("https://{SERVER_NAME}:{}/dns-query", connect.port)
                        .parse()
                        .map_err(|e| format!("DoH3 uri: {e}"))?,
                    server,
                    method: DohMethod::Post,
                    tls_config: tls,
                    timeout: connect.timeout,
                })
                .with_pool(pool),
            ),
            Proto::Doq => {
                let mut config = (*tls).clone();
                config.alpn_protocols = vec![b"doq".to_vec()];
                builder.backend(
                    group,
                    DoqBackend::new(DoqBackendConfig {
                        server,
                        server_name: server_name()?,
                        tls_config: Arc::new(config),
                        connect_timeout: connect.timeout,
                        read_timeout: connect.timeout,
                    })
                    .with_pool(pool),
                )
            }
        }
        .build();
        Ok(Self {
            resolver,
            next_id: AtomicU16::new(1),
        })
    }

    /// The underlying resolver, for cache statistics.
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }
}

fn expected(mix: Mix, response: &Message) -> bool {
    let answers = &response.answers;
    match mix {
        Mix::A => matches!(answers.as_slice(), [one] if matches!(one.rdata, RData::A(_))),
        Mix::Aaaa => matches!(answers.as_slice(), [one] if matches!(one.rdata, RData::Aaaa(_))),
        Mix::Txt => matches!(
            answers.as_slice(),
            [one] if matches!(&one.rdata, RData::Txt(strings) if strings.len() == wire::TXT_STRINGS)
        ),
        Mix::Nx => response.header.rcode == Rcode::NxDomain && answers.is_empty(),
    }
}

impl Contestant for DlContestant {
    type Prepared = Prepared;

    fn prepare(&self, fqdn: &str, mix: Mix) -> Prepared {
        Prepared {
            name: Name::from_ascii(fqdn).expect("harness names are valid"),
            qtype: match mix {
                Mix::A | Mix::Nx => RecordType::A,
                Mix::Aaaa => RecordType::Aaaa,
                Mix::Txt => RecordType::Txt,
            },
            mix,
        }
    }

    async fn query(&self, prepared: &Prepared) -> Outcome {
        let mut query = Message {
            header: Header {
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: prepared.name.clone(),
                qtype: prepared.qtype,
                qclass: Class::In,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        query.set_edns(Some(Edns::new(wire::EDNS_PAYLOAD)));
        match self.resolver.resolve(&query).await {
            Ok(response) if expected(prepared.mix, &response) => Outcome::Ok,
            Ok(_) => Outcome::Mismatch,
            Err(Error::Timeout) => Outcome::Timeout,
            Err(Error::Transport(_)) => Outcome::Error("transport"),
            Err(Error::Tls(_)) => Outcome::Error("tls"),
            Err(_) => Outcome::Error("other"),
        }
    }
}
