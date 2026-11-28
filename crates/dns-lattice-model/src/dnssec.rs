//! DNSSEC wire-record helpers. These helpers do not validate DNS answers.
//!
//! DNSKEY, DS and RRSIG records are still represented by `RData::Unknown` in the
//! message model. These borrowed views allow callers to inspect their RDATA
//! without altering the existing wire representation or allocating.

#[cfg(feature = "dnssec-sha2")]
use sha2::{Digest, Sha256};

use crate::{Class, Name, RData, ResourceRecord};

/// A DNSKEY RDATA view (RFC 4034 section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnskey<'a> {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &'a [u8],
    wire: &'a [u8],
}

impl<'a> Dnskey<'a> {
    /// DNSKEY flags.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Protocol field; DNSSEC validation requires the value 3.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// DNSSEC public-key algorithm number.
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Algorithm-specific public-key bytes.
    pub fn public_key(&self) -> &'a [u8] {
        self.public_key
    }

    /// Parses DNSKEY RDATA, returning `None` when its fixed header is truncated.
    /// Also rejects data exceeding the DNS RDLENGTH limit. This does not
    /// check the protocol value or validate the key.
    pub fn parse(rdata: &'a [u8]) -> Option<Self> {
        if rdata.len() > usize::from(u16::MAX) {
            return None;
        }
        let [a, b, protocol, algorithm, key @ ..] = rdata else {
            return None;
        };
        Some(Self {
            flags: u16::from_be_bytes([*a, *b]),
            protocol: *protocol,
            algorithm: *algorithm,
            public_key: key,
            wire: rdata,
        })
    }

    /// Calculates the RFC 4034 Appendix B key tag.
    ///
    /// Returns `None` if an algorithm 1 key is too short for its legacy tag.
    /// A matching key tag does not authenticate a key or establish trust.
    pub fn key_tag(&self) -> Option<u16> {
        if self.algorithm == 1 {
            let len = self.public_key.len();
            return (len >= 3)
                .then(|| u16::from_be_bytes([self.public_key[len - 3], self.public_key[len - 2]]));
        }
        let mut sum = 0u32;
        for (index, byte) in self.wire.iter().enumerate() {
            sum += if index & 1 == 0 {
                u32::from(*byte) << 8
            } else {
                u32::from(*byte)
            };
        }
        sum += (sum >> 16) & 0xffff;
        Some(sum as u16)
    }

    /// Computes the SHA-256 DS digest of the canonical owner name and this
    /// DNSKEY RDATA (RFC 4509). This does not establish trust in the key.
    #[cfg(feature = "dnssec-sha2")]
    pub fn ds_digest_sha256(&self, owner: &Name) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for label in owner.labels() {
            hasher.update([label.len() as u8]);
            for byte in label {
                hasher.update([byte.to_ascii_lowercase()]);
            }
        }
        hasher.update([0]);
        hasher.update(self.wire);
        hasher.finalize().into()
    }
}

/// A delegation signer (DS) RDATA view (RFC 4034 section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ds<'a> {
    /// Tag of the referenced DNSKEY.
    pub key_tag: u16,
    /// DNSKEY public-key algorithm number.
    pub algorithm: u8,
    /// DS digest algorithm number.
    pub digest_type: u8,
    /// Digest bytes, without validation of algorithm or length.
    pub digest: &'a [u8],
}

impl<'a> Ds<'a> {
    /// Parses DS RDATA, returning `None` when its fixed header is truncated.
    /// Also rejects data exceeding the DNS RDLENGTH limit. The digest and trust
    /// chain are not verified.
    pub fn parse(rdata: &'a [u8]) -> Option<Self> {
        if rdata.len() > usize::from(u16::MAX) {
            return None;
        }
        let [a, b, algorithm, digest_type, digest @ ..] = rdata else {
            return None;
        };
        Some(Self {
            key_tag: u16::from_be_bytes([*a, *b]),
            algorithm: *algorithm,
            digest_type: *digest_type,
            digest,
        })
    }

    /// Tests whether this SHA-256 DS has the key tag, algorithm and digest
    /// of `key` under `owner`. A match alone does not authenticate the DS,
    /// validate key flags/protocol, or validate any DNSSEC signatures.
    /// Unsupported digest types and malformed digest lengths return `false`.
    #[cfg(feature = "dnssec-sha2")]
    pub fn matches_dnskey_sha256(&self, owner: &Name, key: &Dnskey<'_>) -> bool {
        self.digest_type == 2
            && key.key_tag() == Some(self.key_tag)
            && key.algorithm() == self.algorithm
            && self.digest == key.ds_digest_sha256(owner)
    }
}

/// A parsed RRSIG RDATA view (RFC 4034 section 3.1).
///
/// Parsing does not verify the signature, timestamps, signer authority, or
/// the covered RRset. The signer name is owned; the signature borrows RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig<'a> {
    /// Numeric type of the covered RRset.
    pub type_covered: u16,
    /// DNSSEC signature algorithm number.
    pub algorithm: u8,
    /// Number of labels in the original owner name.
    pub labels: u8,
    /// Original TTL of the signed RRset.
    pub original_ttl: u32,
    /// Signature expiration in DNS serial-number time.
    pub expiration: u32,
    /// Signature inception in DNS serial-number time.
    pub inception: u32,
    /// Tag of the signing DNSKEY.
    pub key_tag: u16,
    /// Signer name, which must be uncompressed on the wire.
    pub signer: Name,
    /// Algorithm-specific signature bytes.
    pub signature: &'a [u8],
}

impl<'a> Rrsig<'a> {
    /// Parses RRSIG RDATA. Returns `None` for an oversized or truncated
    /// record, a malformed name, or a compressed signer name.
    pub fn parse(rdata: &'a [u8]) -> Option<Self> {
        if rdata.len() > usize::from(u16::MAX) || rdata.len() < 19 {
            return None;
        }
        let mut cursor = 18;
        // RFC 4034 forbids compression in the signer name. Validate the
        // encoding before using the general DNS name decoder, which permits
        // pointers for ordinary names.
        loop {
            let length = usize::from(*rdata.get(cursor)?);
            if length > 63 {
                return None;
            }
            cursor += 1;
            if length == 0 {
                break;
            }
            cursor = cursor.checked_add(length)?;
            if cursor > rdata.len() {
                return None;
            }
        }
        let mut name_pos = 18;
        let signer = crate::message::decode_name(rdata, &mut name_pos).ok()?;
        debug_assert_eq!(name_pos, cursor);
        Some(Self {
            type_covered: u16::from_be_bytes([rdata[0], rdata[1]]),
            algorithm: rdata[2],
            labels: rdata[3],
            original_ttl: u32::from_be_bytes(rdata[4..8].try_into().ok()?),
            expiration: u32::from_be_bytes(rdata[8..12].try_into().ok()?),
            inception: u32::from_be_bytes(rdata[12..16].try_into().ok()?),
            key_tag: u16::from_be_bytes([rdata[16], rdata[17]]),
            signer,
            signature: &rdata[cursor..],
        })
    }

    /// Builds the canonical bytes covered by this RRSIG for an RRset.
    ///
    /// `owner` and `class` are the RRSIG record's owner and class. Every
    /// record must match them and the covered type. The method reconstructs
    /// wildcard owners, uses the original TTL, sorts canonical RDATA, and
    /// removes duplicate records. It supports the model's typed RDATA and
    /// raw DS/DNSKEY records; other raw types are rejected because their
    /// canonical form may require type-specific processing. This method does
    /// not check signature time, signer authority, or cryptography.
    pub fn signed_data(
        &self,
        owner: &Name,
        class: Class,
        rrset: &[ResourceRecord],
    ) -> Result<Vec<u8>, CanonicalError> {
        if rrset.is_empty() {
            return Err(CanonicalError::EmptySet);
        }
        if class.to_u16() == 0 {
            return Err(CanonicalError::InvalidRecord);
        }
        let labels: Vec<_> = owner.labels().collect();
        let signed_labels = usize::from(self.labels);
        if signed_labels > labels.len() {
            return Err(CanonicalError::InvalidLabels);
        }
        let mut canonical_owner = Vec::new();
        if signed_labels < labels.len() {
            canonical_owner.extend_from_slice(&[1, b'*']);
        }
        for label in &labels[labels.len() - signed_labels..] {
            canonical_owner.push(label.len() as u8);
            canonical_owner.extend(label.iter().map(u8::to_ascii_lowercase));
        }
        canonical_owner.push(0);

        let mut records = Vec::with_capacity(rrset.len());
        for rr in rrset {
            if rr.name != *owner
                || rr.class != class
                || rr.rtype.to_u16() != self.type_covered
                || rr.rdata.record_type().to_u16() != self.type_covered
            {
                return Err(CanonicalError::InvalidRecord);
            }
            let mut data = Vec::new();
            canonical_rdata(&rr.rdata, &mut data)?;
            if data.len() > usize::from(u16::MAX) {
                return Err(CanonicalError::DataTooLong);
            }
            records.push(data);
        }
        records.sort_unstable();
        records.dedup();

        let mut output = Vec::new();
        output.extend_from_slice(&self.type_covered.to_be_bytes());
        output.extend_from_slice(&[self.algorithm, self.labels]);
        output.extend_from_slice(&self.original_ttl.to_be_bytes());
        output.extend_from_slice(&self.expiration.to_be_bytes());
        output.extend_from_slice(&self.inception.to_be_bytes());
        output.extend_from_slice(&self.key_tag.to_be_bytes());
        canonical_name(&self.signer, &mut output);
        for data in records {
            output.extend_from_slice(&canonical_owner);
            output.extend_from_slice(&self.type_covered.to_be_bytes());
            output.extend_from_slice(&class.to_u16().to_be_bytes());
            output.extend_from_slice(&self.original_ttl.to_be_bytes());
            output.extend_from_slice(&(data.len() as u16).to_be_bytes());
            output.extend_from_slice(&data);
        }
        Ok(output)
    }
}

/// Why a DNSSEC RRset cannot be converted to supported canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    /// The RRset contains no records.
    EmptySet,
    /// RRSIG label count exceeds the owner label count.
    InvalidLabels,
    /// A record's owner, class, type or data does not match the RRset.
    InvalidRecord,
    /// The raw record type needs canonicalization not implemented here.
    UnsupportedType,
    /// Encoded record data exceeds the DNS RDLENGTH limit.
    DataTooLong,
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSSEC canonicalization failed: {self:?}")
    }
}
impl std::error::Error for CanonicalError {}

fn canonical_name(name: &Name, output: &mut Vec<u8>) {
    for label in name.labels() {
        output.push(label.len() as u8);
        output.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    output.push(0);
}

fn canonical_rdata(rdata: &RData, output: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match rdata {
        RData::Cname(name) | RData::Ptr(name) | RData::Ns(name) => canonical_name(name, output),
        RData::Mx {
            preference,
            exchange,
        } => {
            output.extend_from_slice(&preference.to_be_bytes());
            canonical_name(exchange, output);
        }
        RData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            canonical_name(mname, output);
            canonical_name(rname, output);
            for field in [serial, refresh, retry, expire, minimum] {
                output.extend_from_slice(&field.to_be_bytes());
            }
        }
        RData::Unknown {
            rtype: 43 | 48,
            data,
        } => output.extend_from_slice(data),
        RData::Unknown { .. } => return Err(CanonicalError::UnsupportedType),
        other => other
            .encode(output)
            .map_err(|_| CanonicalError::InvalidRecord)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnskey_parses_and_calculates_even_and_odd_length_tags() {
        let key = Dnskey::parse(&[1, 1, 3, 8, 1, 2]).unwrap();
        assert_eq!((key.flags, key.protocol, key.algorithm), (257, 3, 8));
        assert_eq!(key.public_key, [1, 2]);
        assert_eq!(key.key_tag(), Some(0x050b));
        assert_eq!(
            Dnskey::parse(&[1, 1, 3, 8, 1]).unwrap().key_tag(),
            Some(0x0509)
        );
        assert!(Dnskey::parse(&[1, 1, 3]).is_none());
    }

    #[test]
    fn rfc_4034_ds_example_key_tag() {
        // RFC 4034 section 5.4, DNSKEY RDATA in wire form.
        let mut wire = vec![1, 0, 3, 5];
        wire.extend_from_slice(&[
            1, 3, 158, 138, 36, 116, 24, 227, 24, 144, 59, 33, 90, 132, 138, 207, 213, 243, 127, 2,
            107, 212, 6, 45, 178, 108, 119, 76, 105, 9, 104, 213, 213, 109, 248, 191, 218, 145,
            230, 243, 109, 154, 39, 152, 136, 244, 19, 51, 53, 124, 94, 96, 41, 153, 13, 16, 253,
            245, 102, 48, 98, 165, 18, 118, 51, 38, 152, 10, 97, 93, 219, 241, 122, 5, 221, 252,
            206, 126, 95, 179, 171, 204, 160, 90, 49, 176, 149, 116, 82, 212, 82, 30, 131, 135, 7,
            137, 6, 49, 21, 191, 151, 246, 195, 8, 204, 245, 124, 220, 156, 231, 254, 16, 246, 237,
            27, 208, 204, 6, 96, 3, 140, 80, 220, 219, 15, 235, 150, 60, 47, 23,
        ]);
        assert_eq!(Dnskey::parse(&wire).unwrap().key_tag(), Some(60485));
        #[cfg(feature = "dnssec-sha2")]
        {
            let key = Dnskey::parse(&wire).unwrap();
            let expected = [
                0xd4, 0xb7, 0xd5, 0x20, 0xe7, 0xbb, 0x5f, 0x0f, 0x67, 0x67, 0x4a, 0x0c, 0xce, 0xb1,
                0xe3, 0xe0, 0x61, 0x4b, 0x93, 0xc4, 0xf9, 0xe9, 0x9b, 0x83, 0x83, 0xf6, 0xa1, 0xe4,
                0x46, 0x9d, 0xa5, 0x0a,
            ];
            let owner = Name::from_ascii("DsKey.Example.COM").unwrap();
            assert_eq!(key.ds_digest_sha256(&owner), expected);
            let ds = Ds {
                key_tag: 60485,
                algorithm: 5,
                digest_type: 2,
                digest: &expected,
            };
            assert!(ds.matches_dnskey_sha256(&owner, &key));
            assert!(!ds.matches_dnskey_sha256(&Name::root(), &key));
            assert!(!Ds { key_tag: 1, ..ds }.matches_dnskey_sha256(&owner, &key));
            assert!(!Ds { algorithm: 8, ..ds }.matches_dnskey_sha256(&owner, &key));
            assert!(
                !Ds {
                    digest_type: 1,
                    ..ds
                }
                .matches_dnskey_sha256(&owner, &key)
            );
            assert!(
                !Ds {
                    digest: &expected[..31],
                    ..ds
                }
                .matches_dnskey_sha256(&owner, &key)
            );
        }
    }

    #[test]
    fn legacy_key_tag_requires_three_key_octets() {
        assert_eq!(
            Dnskey::parse(&[1, 0, 3, 1, 8, 9, 10]).unwrap().key_tag(),
            Some(0x0809)
        );
        assert_eq!(Dnskey::parse(&[1, 0, 3, 1, 8, 9]).unwrap().key_tag(), None);
    }

    #[test]
    fn ds_parses_without_claiming_digest_validity() {
        let ds = Ds::parse(&[0x12, 0x34, 8, 2, 0xaa, 0xbb]).unwrap();
        assert_eq!((ds.key_tag, ds.algorithm, ds.digest_type), (0x1234, 8, 2));
        assert_eq!(ds.digest, [0xaa, 0xbb]);
        assert!(Ds::parse(&[0, 1, 8]).is_none());
        assert!(Ds::parse(&vec![0; 65536]).is_none());
        assert!(Dnskey::parse(&vec![0; 65536]).is_none());
    }

    #[test]
    fn rrsig_parses_fields_and_preserves_signature() {
        let data = [
            0, 1, 8, 2, 0, 0, 14, 16, 0, 0, 0, 9, 0, 0, 0, 4, 0x12, 0x34, 3, b'W', b'W', b'W', 7,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0xaa, 0xbb,
        ];
        let sig = Rrsig::parse(&data).unwrap();
        assert_eq!(
            (
                sig.type_covered,
                sig.algorithm,
                sig.labels,
                sig.original_ttl
            ),
            (1, 8, 2, 3600)
        );
        assert_eq!((sig.expiration, sig.inception, sig.key_tag), (9, 4, 0x1234));
        assert_eq!(sig.signer, Name::from_ascii("www.example").unwrap());
        assert_eq!(sig.signature, [0xaa, 0xbb]);
    }

    #[test]
    fn rrsig_rejects_bad_names_and_truncated_headers() {
        assert!(Rrsig::parse(&[0; 18]).is_none());
        let mut data = vec![0; 18];
        data.extend_from_slice(&[0xc0, 0]);
        assert!(Rrsig::parse(&data).is_none());
        data.truncate(18);
        data.extend_from_slice(&[4, b'a', b'b']);
        assert!(Rrsig::parse(&data).is_none());
        data.truncate(18);
        data.extend_from_slice(&[0]);
        assert!(Rrsig::parse(&data).unwrap().signer.is_root());
        assert!(Rrsig::parse(&vec![0; 65536]).is_none());
    }

    #[test]
    fn signed_data_sorts_deduplicates_and_reconstructs_wildcard() {
        use crate::RecordType;
        use std::net::Ipv4Addr;
        let owner = Name::from_ascii("WWW.Example.COM").unwrap();
        let sig = Rrsig {
            type_covered: 1,
            algorithm: 8,
            labels: 2,
            original_ttl: 300,
            expiration: 8,
            inception: 4,
            key_tag: 42,
            signer: Name::from_ascii("EXAMPLE.com").unwrap(),
            signature: &[],
        };
        let record = |addr| ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 1,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, addr)),
        };
        let data = sig
            .signed_data(&owner, Class::In, &[record(2), record(1), record(2)])
            .unwrap();
        let mut expected = vec![0, 1, 8, 2, 0, 0, 1, 44, 0, 0, 0, 8, 0, 0, 0, 4, 0, 42];
        expected.extend_from_slice(b"\x07example\x03com\0");
        for addr in [1, 2] {
            expected.extend_from_slice(b"\x01*\x07example\x03com\0");
            expected.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, addr]);
        }
        assert_eq!(data, expected);
        assert_eq!(
            sig.signed_data(&owner, Class::In, &[]),
            Err(CanonicalError::EmptySet)
        );
        assert_eq!(
            sig.signed_data(&owner, Class::Ch, &[record(1)]),
            Err(CanonicalError::InvalidRecord)
        );
        let mut invalid = sig.clone();
        invalid.labels = 4;
        assert_eq!(
            invalid.signed_data(&owner, Class::In, &[record(1)]),
            Err(CanonicalError::InvalidLabels)
        );
    }

    #[test]
    fn signed_data_canonicalizes_names_and_rejects_unknown_type() {
        use crate::RecordType;
        let owner = Name::from_ascii("Example.COM").unwrap();
        let mut sig = Rrsig {
            type_covered: 5,
            algorithm: 8,
            labels: 2,
            original_ttl: 1,
            expiration: 2,
            inception: 1,
            key_tag: 3,
            signer: owner.clone(),
            signature: &[],
        };
        let cname = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::Cname,
            class: Class::In,
            ttl: 5,
            rdata: RData::Cname(Name::from_ascii("Alias.Example").unwrap()),
        };
        assert!(
            sig.signed_data(&owner, Class::In, &[cname])
                .unwrap()
                .ends_with(b"\x05alias\x07example\0")
        );
        sig.type_covered = 47;
        let unknown = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::Other(47),
            class: Class::In,
            ttl: 5,
            rdata: RData::Unknown {
                rtype: 47,
                data: vec![0],
            },
        };
        assert_eq!(
            sig.signed_data(&owner, Class::In, &[unknown]),
            Err(CanonicalError::UnsupportedType)
        );
    }
}
