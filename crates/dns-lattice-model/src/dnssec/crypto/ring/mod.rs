//! DNSSEC signature verification using ring.

mod ecdsa;
mod ed25519;
mod rsa;

use super::{CryptoError, SignatureVerifier};

/// ring backend: RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256 (13),
/// P-384 (14), and Ed25519 (15). RSA moduli must be 1024–8192 bits.
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
            8 | 10 => rsa::verify(algorithm, public_key, data, signature),
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
            RingVerifier.verify(200, &[], &[], &[]),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        for algorithm in [8, 10, 13, 14, 15] {
            assert_eq!(
                RingVerifier.verify(algorithm, &[], &[], &[]),
                Err(CryptoError::InvalidSignature)
            );
        }
    }
}
