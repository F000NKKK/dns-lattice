//! DNSSEC ECDSA P-256 and P-384 (RFC 6605).

use super::CryptoError;

pub(super) fn verify(
    algorithm: u8,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let (verifier, key_len): (&dyn ring::signature::VerificationAlgorithm, usize) = match algorithm
    {
        13 => (&ring::signature::ECDSA_P256_SHA256_FIXED, 64),
        14 => (&ring::signature::ECDSA_P384_SHA384_FIXED, 96),
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };
    if public_key.len() != key_len {
        return Err(CryptoError::InvalidSignature);
    }
    // DNSKEY stores X || Y, whereas ring expects an uncompressed SEC1 point.
    let mut point = [0u8; 97];
    point[0] = 4;
    point[1..=key_len].copy_from_slice(public_key);
    ring::signature::UnparsedPublicKey::new(verifier, &point[..=key_len])
        .verify(data, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::super::RingVerifier;
    use crate::dnssec::{Dnskey, Rrsig, SignatureError};
    use crate::{Class, Name, RData, RecordType, ResourceRecord};

    #[test]
    fn rfc_6605_ecdsa_vectors_and_tampering() {
        type Vector<'a> = (u8, u16, u32, u32, &'a [u8], &'a [u8]);
        let vectors: &[Vector<'_>] = &[
            (
                13,
                55648,
                1284026679,
                1281607479,
                &[
                    26, 136, 200, 134, 21, 212, 55, 251, 184, 191, 158, 25, 66, 161, 146, 159, 40,
                    86, 39, 6, 174, 108, 43, 211, 153, 231, 177, 191, 182, 209, 233, 231, 91, 146,
                    180, 170, 66, 145, 122, 225, 198, 27, 112, 30, 240, 53, 195, 254, 123, 227, 0,
                    156, 186, 254, 90, 47, 113, 49, 108, 144, 45, 207, 13, 0,
                ],
                &[
                    171, 30, 176, 45, 138, 166, 135, 233, 125, 160, 34, 147, 55, 170, 136, 115,
                    230, 240, 235, 38, 190, 40, 159, 40, 51, 61, 24, 63, 93, 59, 122, 149, 192,
                    200, 105, 173, 251, 116, 141, 174, 227, 197, 40, 110, 237, 102, 130, 193, 46,
                    85, 51, 24, 107, 172, 237, 156, 38, 193, 103, 169, 235, 174, 149, 11,
                ],
            ),
            (
                14,
                10771,
                1284027625,
                1281608425,
                &[
                    196, 166, 26, 54, 21, 157, 24, 231, 201, 250, 115, 235, 47, 207, 218, 174, 76,
                    31, 216, 70, 55, 48, 50, 126, 72, 74, 202, 138, 240, 85, 74, 233, 181, 195,
                    247, 160, 177, 123, 210, 0, 59, 77, 38, 28, 158, 155, 148, 66, 58, 152, 16,
                    232, 175, 23, 212, 52, 82, 18, 74, 219, 97, 15, 142, 7, 235, 252, 254, 229,
                    248, 228, 208, 112, 99, 202, 233, 235, 145, 122, 26, 91, 171, 240, 143, 230,
                    149, 83, 96, 23, 165, 191, 169, 50, 55, 238, 110, 52,
                ],
                &[
                    252, 190, 97, 12, 162, 47, 24, 60, 136, 213, 247, 0, 69, 125, 243, 235, 154,
                    171, 152, 251, 21, 207, 189, 208, 15, 83, 43, 228, 33, 42, 58, 34, 207, 247,
                    152, 113, 66, 139, 174, 174, 129, 130, 121, 147, 175, 204, 86, 177, 177, 63, 6,
                    150, 190, 248, 133, 182, 175, 68, 166, 178, 36, 219, 178, 116, 43, 179, 89, 52,
                    146, 61, 220, 251, 194, 122, 151, 47, 150, 221, 112, 156, 238, 177, 217, 200,
                    209, 20, 140, 68, 236, 113, 192, 104, 169, 89, 194, 102,
                ],
            ),
        ];
        let owner = Name::from_ascii("www.example.net").unwrap();
        let signer = Name::from_ascii("example.net").unwrap();
        for &(algorithm, tag, expiration, inception, public, signature) in vectors {
            let mut wire = vec![1, 1, 3, algorithm];
            wire.extend_from_slice(public);
            let key = Dnskey::parse(&wire).unwrap();
            assert_eq!(key.key_tag(), Some(tag));
            let sig = Rrsig {
                type_covered: 1,
                algorithm,
                labels: 3,
                original_ttl: 3600,
                expiration,
                inception,
                key_tag: tag,
                signer: signer.clone(),
                signature,
            };
            let rr = ResourceRecord {
                name: owner.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 3600,
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
                    inception
                ),
                Ok(())
            );
            let mut bad = rr;
            bad.rdata = RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2));
            assert_eq!(
                sig.verify(&RingVerifier, &signer, &key, &owner, Class::In, &[bad]),
                Err(SignatureError::Crypto(super::CryptoError::InvalidSignature))
            );
        }
    }

    #[test]
    fn malformed_lengths_are_rejected() {
        for (algorithm, length) in [(13, 64), (14, 96)] {
            let key = vec![0; length];
            assert_eq!(
                super::verify(algorithm, &key[..length - 1], b"message", &[]),
                Err(super::CryptoError::InvalidSignature)
            );
            assert_eq!(
                super::verify(algorithm, &key, b"message", &[0; 4]),
                Err(super::CryptoError::InvalidSignature)
            );
        }
    }
}
