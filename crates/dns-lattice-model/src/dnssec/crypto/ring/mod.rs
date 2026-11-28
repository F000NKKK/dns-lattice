//! DNSSEC signature verification using ring.

mod ecdsa;
mod ed25519;

use super::{CryptoError, SignatureVerifier};

/// ring backend: ECDSA P-256 (13), P-384 (14), and Ed25519 (15).
#[derive(Debug, Default, Clone, Copy)]
pub struct RingVerifier;

impl SignatureVerifier for RingVerifier {
    fn verify(
        &self,
        algorithm: u8,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match algorithm {
            13 | 14 => ecdsa::verify(algorithm, public_key, data, signature),
            15 => ed25519::verify(public_key, data, signature),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_and_malformed_keys() {
        assert_eq!(
            RingVerifier.verify(8, &[], &[], &[]),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        for algorithm in [13, 14, 15] {
            assert_eq!(
                RingVerifier.verify(algorithm, &[], &[], &[]),
                Err(CryptoError::InvalidSignature)
            );
        }
    }
}
