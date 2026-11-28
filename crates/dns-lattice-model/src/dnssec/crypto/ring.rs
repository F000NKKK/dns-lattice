//! Signature algorithms implemented with ring.

use super::{CryptoError, SignatureVerifier};

/// DNSSEC signature backend using ring. Currently supports Ed25519 (15).
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
        if algorithm != 15 {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
            .verify(data, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_algorithm_and_malformed_ed25519_key() {
        assert_eq!(
            RingVerifier.verify(8, &[], &[], &[]),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        assert_eq!(
            RingVerifier.verify(15, &[], &[], &[]),
            Err(CryptoError::InvalidSignature)
        );
    }
}
