//! TLS fixture: a throwaway CA and a leaf certificate for the loopback
//! upstream.
//!
//! [`Fixture::generate`] creates a fresh CA and a leaf certificate valid for
//! [`SERVER_NAME`] and `127.0.0.1`. The responder serves the leaf; both
//! contestants trust only the CA, through the one
//! [`client_config`] so that roots, crypto provider, protocol versions and
//! resumption policy are identical on both sides. The client configuration
//! leaves ALPN empty: hickory fills in the protocol's own ALPN when the list
//! is empty, and the dns-lattice backends set (DoH) or require (DoQ) theirs
//! on a clone.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// The DNS name the leaf certificate is valid for and the clients verify.
pub const SERVER_NAME: &str = "dns.bench.test";

/// An error generating or loading the fixture.
#[derive(Debug)]
pub struct FixtureError(String);

impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS fixture: {}", self.0)
    }
}

impl std::error::Error for FixtureError {}

impl FixtureError {
    fn new(context: &str, err: impl std::fmt::Display) -> Self {
        Self(format!("{context}: {err}"))
    }
}

/// A CA certificate plus a leaf certificate and key signed by it.
pub struct Fixture {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    leaf_key: Vec<u8>,
}

impl Fixture {
    /// Generates a fresh CA and leaf certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation fails.
    pub fn generate() -> Result<Self, FixtureError> {
        let ca_key = KeyPair::generate().map_err(|e| FixtureError::new("CA key", e))?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "dns-lattice benchmark CA");
        ca_params.distinguished_name = name;
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
            .map_err(|e| FixtureError::new("CA certificate", e))?;

        let leaf_key = KeyPair::generate().map_err(|e| FixtureError::new("leaf key", e))?;
        let mut leaf_params = CertificateParams::default();
        let dns_name = SERVER_NAME
            .try_into()
            .map_err(|e| FixtureError::new("server name", e))?;
        leaf_params.subject_alt_names = vec![
            SanType::DnsName(dns_name),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca)
            .map_err(|e| FixtureError::new("leaf certificate", e))?;

        Ok(Self {
            ca: ca.der().clone(),
            leaf: leaf.der().clone(),
            leaf_key: leaf_key.serialize_der(),
        })
    }

    /// The CA certificate in DER form (what clients are given to trust).
    pub fn ca_der(&self) -> &[u8] {
        self.ca.as_ref()
    }

    /// A rustls server configuration serving the leaf certificate, with
    /// the given ALPN protocols.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not match the certificate.
    pub fn server_config(&self, alpn: &[&[u8]]) -> Result<ServerConfig, FixtureError> {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.leaf_key.clone()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| FixtureError::new("protocol versions", e))?
            .with_no_client_auth()
            .with_single_cert(vec![self.leaf.clone(), self.ca.clone()], key)
            .map_err(|e| FixtureError::new("server config", e))?;
        config.alpn_protocols = alpn.iter().map(|proto| proto.to_vec()).collect();
        Ok(config)
    }
}

/// The shared client configuration: aws-lc-rs, default protocol versions,
/// trusting only the CA given as DER, ALPN empty, default session
/// resumption.
///
/// # Errors
///
/// Returns an error if `ca_der` is not a certificate.
pub fn client_config(ca_der: &[u8]) -> Result<ClientConfig, FixtureError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|e| FixtureError::new("CA root", e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| FixtureError::new("protocol versions", e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}
