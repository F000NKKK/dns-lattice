//! DNSSEC RSA/SHA-256 and RSA/SHA-512 (RFC 3110 and RFC 5702).

use super::CryptoError;

fn components(key: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = usize::from(*key.first()?);
    let (header, exponent_len) = if first == 0 {
        let len = usize::from(u16::from_be_bytes([*key.get(1)?, *key.get(2)?]));
        if len <= 255 {
            return None;
        }
        (3, len)
    } else {
        (1, first)
    };
    let end = header + exponent_len;
    let exponent = key.get(header..end)?;
    let modulus = key.get(end..)?;
    if exponent.first().copied().unwrap_or(0) == 0 || modulus.first().copied().unwrap_or(0) == 0 {
        return None;
    }
    Some((exponent, modulus))
}

pub(super) fn verify(
    algorithm: u8,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verifier = match algorithm {
        8 => &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        10 => &ring::signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };
    let (exponent, modulus) = components(public_key).ok_or(CryptoError::InvalidSignature)?;
    ring::signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    }
    .verify(verifier, data, signature)
    .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rsa_wire_exponents_and_rejects_nonminimal_or_truncated_keys() {
        assert_eq!(
            components(&[3, 1, 0, 1, 0x80]),
            Some((&[1, 0, 1][..], &[0x80][..]))
        );
        for key in [
            &[][..],
            &[0][..],
            &[0, 1][..],
            &[0, 0, 3, 1, 0, 1, 0x80][..],
            &[1, 0, 1][..],
            &[1, 1, 0][..],
            &[3, 1, 0][..],
            &[1, 1][..],
        ] {
            assert!(components(key).is_none(), "{key:?}");
        }
        let mut long = vec![0, 1, 0];
        long.extend_from_slice(&[1; 256]);
        long.push(0x80);
        assert_eq!(components(&long).unwrap().0.len(), 256);
    }

    #[test]
    fn checks_rsa_sha256_and_sha512_and_detects_tampering() {
        use super::super::RingVerifier;
        use crate::dnssec::{Dnskey, Rrsig, SignatureError};
        use crate::{Class, Name, RData, RecordType, ResourceRecord};

        // Independent fixtures were signed with Python cryptography; the
        // corresponding private key is not stored in the repository.
        let public = include_bytes!("../../../../tests/data/dnssec-rsa-key.bin");
        let sig256 = include_bytes!("../../../../tests/data/dnssec-rsa-sha256.bin");
        let sig512 = include_bytes!("../../../../tests/data/dnssec-rsa-sha512.bin");
        let owner = Name::from_ascii("www.example.com").unwrap();
        let signer = Name::from_ascii("example.com").unwrap();
        for (algorithm, signature) in [(8, &sig256[..]), (10, &sig512[..])] {
            let mut wire = vec![1, 1, 3, algorithm];
            wire.extend_from_slice(public);
            let key = Dnskey::parse(&wire).unwrap();
            let mut sig = Rrsig {
                type_covered: 1,
                algorithm,
                labels: 3,
                original_ttl: 300,
                expiration: 10,
                inception: 1,
                key_tag: key.key_tag().unwrap(),
                signer: signer.clone(),
                signature,
            };
            let mut rr = ResourceRecord {
                name: owner.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 1,
                rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            };
            assert_eq!(
                sig.verify_at(
                    &RingVerifier,
                    &signer,
                    &key,
                    &owner,
                    Class::In,
                    std::slice::from_ref(&rr),
                    1
                ),
                Ok(())
            );
            sig.signature = &signature[..signature.len() - 1];
            assert_eq!(
                sig.verify(
                    &RingVerifier,
                    &signer,
                    &key,
                    &owner,
                    Class::In,
                    std::slice::from_ref(&rr)
                ),
                Err(SignatureError::Crypto(CryptoError::InvalidSignature))
            );
            sig.signature = signature;
            rr.rdata = RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2));
            assert_eq!(
                sig.verify(&RingVerifier, &signer, &key, &owner, Class::In, &[rr]),
                Err(SignatureError::Crypto(CryptoError::InvalidSignature))
            );
        }
    }
}
