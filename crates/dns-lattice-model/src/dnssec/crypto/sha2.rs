//! SHA-2 DS digest implementations (RFC 4509 and RFC 6605).

use super::DsDigest;
use crate::{Name, dnssec::Dnskey};
use sha2::{Digest, Sha256, Sha384};

fn compute<D: Digest>(owner: &Name, key: &Dnskey<'_>) -> Vec<u8> {
    let mut hasher = D::new();
    for label in owner.labels() {
        hasher.update([label.len() as u8]);
        for byte in label {
            hasher.update([byte.to_ascii_lowercase()]);
        }
    }
    hasher.update([0]);
    hasher.update(key.wire);
    hasher.finalize().to_vec()
}

/// SHA-256 DS digest (type 2).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256Digest;

impl DsDigest for Sha256Digest {
    fn digest_type(&self) -> u8 {
        2
    }
    fn digest(&self, owner: &Name, key: &Dnskey<'_>) -> Vec<u8> {
        compute::<Sha256>(owner, key)
    }
}

/// SHA-384 DS digest (type 4).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha384Digest;

impl DsDigest for Sha384Digest {
    fn digest_type(&self) -> u8 {
        4
    }
    fn digest(&self, owner: &Name, key: &Dnskey<'_>) -> Vec<u8> {
        compute::<Sha384>(owner, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::Ds;

    #[test]
    fn rfc_6605_sha384_ds_matches_dnskey() {
        let mut wire = vec![1, 1, 3, 14];
        wire.extend_from_slice(&[
            196, 166, 26, 54, 21, 157, 24, 231, 201, 250, 115, 235, 47, 207, 218, 174, 76, 31, 216,
            70, 55, 48, 50, 126, 72, 74, 202, 138, 240, 85, 74, 233, 181, 195, 247, 160, 177, 123,
            210, 0, 59, 77, 38, 28, 158, 155, 148, 66, 58, 152, 16, 232, 175, 23, 212, 52, 82, 18,
            74, 219, 97, 15, 142, 7, 235, 252, 254, 229, 248, 228, 208, 112, 99, 202, 233, 235,
            145, 122, 26, 91, 171, 240, 143, 230, 149, 83, 96, 23, 165, 191, 169, 50, 55, 238, 110,
            52,
        ]);
        let expected = [
            0x72, 0xd7, 0xb6, 0x29, 0x76, 0xce, 0x06, 0x43, 0x8e, 0x9c, 0x0b, 0xf3, 0x19, 0x01,
            0x3c, 0xf8, 0x01, 0xf0, 0x9e, 0xcc, 0x84, 0xb8, 0xd7, 0xe9, 0x49, 0x5f, 0x27, 0xe3,
            0x05, 0xc6, 0xa9, 0xb0, 0x56, 0x3a, 0x9b, 0x5f, 0x4d, 0x28, 0x84, 0x05, 0xc3, 0x00,
            0x8a, 0x94, 0x6d, 0xf9, 0x83, 0xd6,
        ];
        let key = Dnskey::parse(&wire).unwrap();
        let name = Name::from_ascii("EXAMPLE.net").unwrap();
        assert_eq!(Sha384Digest.digest(&name, &key), expected);
        let ds = Ds {
            key_tag: 10771,
            algorithm: 14,
            digest_type: 4,
            digest: &expected,
        };
        assert!(ds.matches_dnskey(&Sha384Digest, &name, &key));
        assert!(!ds.matches_dnskey(&Sha256Digest, &name, &key));
        assert!(!ds.matches_dnskey(&Sha384Digest, &Name::root(), &key));
        assert!(
            !Ds {
                digest: &expected[..47],
                ..ds
            }
            .matches_dnskey(&Sha384Digest, &name, &key)
        );
    }
}
