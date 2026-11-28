//! DNSSEC Ed25519 (RFC 8080).

use super::CryptoError;

pub(super) fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(data, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}
