//! Pluggable, runtime-independent DNSSEC signature verification backends.

#[cfg(feature = "dnssec-ring")]
mod ring;
#[cfg(feature = "dnssec-ring")]
pub use ring::RingVerifier;

/// A cryptographic backend for DNSSEC signature algorithms.
///
/// Inputs are the DNSKEY public-key field, canonical signed data, and the
/// RRSIG signature field. Implementations must reject malformed keys and
/// signatures. This trait does not establish DNSSEC trust or validate time.
pub trait SignatureVerifier: Send + Sync {
    /// Checks a signature using a DNSSEC algorithm number.
    fn verify(
        &self,
        algorithm: u8,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Result of a cryptographic signature operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// This backend does not support the requested algorithm.
    UnsupportedAlgorithm,
    /// The key or signature is malformed, or signature verification failed.
    InvalidSignature,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSSEC cryptographic verification failed: {self:?}")
    }
}
impl std::error::Error for CryptoError {}
