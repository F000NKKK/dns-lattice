//! DNSSEC wire-record helpers. These helpers do not validate DNS answers.
//!
//! DNSKEY, DS and RRSIG records are still represented by `RData::Unknown` in the
//! message model. These borrowed views allow callers to inspect their RDATA
//! without altering the existing wire representation or allocating.

/// Runtime-independent signature backend interface and implementations.
pub mod crypto;

use crypto::{CryptoError, DsDigest, SignatureVerifier};

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

    /// Tests whether this DS has the key tag, algorithm and digest
    /// of `key` under `owner`. A match alone does not authenticate the DS,
    /// validate key flags/protocol, or validate any DNSSEC signatures.
    /// A digest type mismatch or malformed digest length returns `false`.
    pub fn matches_dnskey(
        &self,
        digest: &(impl DsDigest + ?Sized),
        owner: &Name,
        key: &Dnskey<'_>,
    ) -> bool {
        self.digest_type == digest.digest_type()
            && key.key_tag() == Some(self.key_tag)
            && key.algorithm() == self.algorithm
            && self.digest == digest.digest(owner, key)
    }

    /// Checks a DNSKEY RRset against this already-authenticated DS record.
    ///
    /// The DS owner must have been authenticated as `zone` by the caller.
    /// This checks the digest against every DNSKEY candidate and requires a
    /// valid, currently effective RRSIG made by a matching key. One DS and
    /// one RRSIG are checked per call; digest preference, multiple trust
    /// anchors, parent-zone validation and response validation remain the
    /// caller's responsibility. A result is meaningful only if `digest` and
    /// `verifier` are trusted implementations.
    pub fn verify_dnskey_rrset(
        &self,
        digest: &(impl DsDigest + ?Sized),
        verifier: &(impl SignatureVerifier + ?Sized),
        zone: &Name,
        rrset: &[ResourceRecord],
        signature: &Rrsig<'_>,
        now: u32,
    ) -> Result<(), DnskeyAuthenticationError> {
        if self.digest_type != digest.digest_type() {
            return Err(DnskeyAuthenticationError::UnsupportedDigest);
        }
        if signature.type_covered != 48 || rrset.is_empty() {
            return Err(DnskeyAuthenticationError::InvalidRrset);
        }
        let class = rrset[0].class;
        let mut last_error = None;
        for rr in rrset {
            let RData::Unknown { rtype: 48, data } = &rr.rdata else {
                continue;
            };
            let Some(key) = Dnskey::parse(data) else {
                continue;
            };
            if !self.matches_dnskey(digest, zone, &key) {
                continue;
            }
            match signature.verify_at(verifier, zone, &key, zone, class, rrset, now) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.map_or(
            DnskeyAuthenticationError::NoMatchingKey,
            DnskeyAuthenticationError::Signature,
        ))
    }
}

/// Failure to check a DNSKEY RRset against a supplied authenticated DS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnskeyAuthenticationError {
    /// The selected digest implementation does not match the DS digest type.
    UnsupportedDigest,
    /// The RRset is empty or the signature covers a type other than DNSKEY.
    InvalidRrset,
    /// No DNSKEY in the RRset matches the supplied DS.
    NoMatchingKey,
    /// The matching key did not produce a valid signature on this RRset.
    Signature(SignatureError),
}

impl std::fmt::Display for DnskeyAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSKEY RRset authentication failed: {self:?}")
    }
}
impl std::error::Error for DnskeyAuthenticationError {}

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
    /// Checks the RRSIG time window against Unix seconds modulo 2³², using
    /// DNS serial-number arithmetic. Inception and expiration are inclusive.
    /// Windows of 2³¹ seconds or longer are ambiguous and return `false`.
    /// The caller supplies time; no clock or runtime is required.
    pub fn valid_at(&self, now: u32) -> bool {
        let duration = self.expiration.wrapping_sub(self.inception);
        duration < (1 << 31) && now.wrapping_sub(self.inception) <= duration
    }

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

    /// Verifies an RRSIG over a supported RRset using `verifier`.
    ///
    /// This checks the DNSKEY owner against the signer name, zone-key flag,
    /// protocol, algorithm, key tag, signer ancestry and cryptographic
    /// signature. It does **not** authenticate the DNSKEY or DS, check the
    /// signature's validity period, establish a trust chain, or validate a
    /// DNS response. Callers must perform those checks separately.
    pub fn verify(
        &self,
        verifier: &(impl SignatureVerifier + ?Sized),
        key_owner: &Name,
        key: &Dnskey<'_>,
        owner: &Name,
        class: Class,
        rrset: &[ResourceRecord],
    ) -> Result<(), SignatureError> {
        if *key_owner != self.signer
            || !owner.ends_with(&self.signer)
            || usize::from(self.labels) < self.signer.label_count()
            || key.flags() & 0x0100 == 0
            || key.protocol() != 3
            || key.algorithm() != self.algorithm
            || key.key_tag() != Some(self.key_tag)
        {
            return Err(SignatureError::InvalidKey);
        }
        let data = self
            .signed_data(owner, class, rrset)
            .map_err(SignatureError::Canonical)?;
        verifier
            .verify(self.algorithm, key.public_key(), &data, self.signature)
            .map_err(SignatureError::Crypto)
    }

    /// Checks the validity window and verifies the signature.
    ///
    /// `now` is Unix time in seconds modulo 2³². Like [`Self::verify`],
    /// this does not authenticate the DNSKEY or establish a trust chain.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_at(
        &self,
        verifier: &(impl SignatureVerifier + ?Sized),
        key_owner: &Name,
        key: &Dnskey<'_>,
        owner: &Name,
        class: Class,
        rrset: &[ResourceRecord],
        now: u32,
    ) -> Result<(), SignatureError> {
        if !self.valid_at(now) {
            return Err(SignatureError::OutsideValidityPeriod);
        }
        self.verify(verifier, key_owner, key, owner, class, rrset)
    }
}

/// Failure to cryptographically check a supported DNSSEC signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature is not currently valid or its time window is ambiguous.
    OutsideValidityPeriod,
    /// The DNSKEY or signer identity does not match the RRSIG.
    InvalidKey,
    /// The covered RRset cannot be canonicalized.
    Canonical(CanonicalError),
    /// The cryptographic backend rejected the algorithm, key, or signature.
    Crypto(CryptoError),
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSSEC signature check failed: {self:?}")
    }
}

impl std::error::Error for SignatureError {}

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
            assert_eq!(crypto::Sha256Digest.digest(&owner, &key), expected);
            let ds = Ds {
                key_tag: 60485,
                algorithm: 5,
                digest_type: 2,
                digest: &expected,
            };
            assert!(ds.matches_dnskey(&crypto::Sha256Digest, &owner, &key));
            assert!(!ds.matches_dnskey(&crypto::Sha256Digest, &Name::root(), &key));
            assert!(!Ds { key_tag: 1, ..ds }.matches_dnskey(&crypto::Sha256Digest, &owner, &key));
            assert!(!Ds { algorithm: 8, ..ds }.matches_dnskey(&crypto::Sha256Digest, &owner, &key));
            assert!(
                !Ds {
                    digest_type: 1,
                    ..ds
                }
                .matches_dnskey(&crypto::Sha256Digest, &owner, &key)
            );
            assert!(
                !Ds {
                    digest: &expected[..31],
                    ..ds
                }
                .matches_dnskey(&crypto::Sha256Digest, &owner, &key)
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
    fn ds_accepts_a_custom_digest_backend_without_features() {
        struct External;
        impl DsDigest for External {
            fn digest_type(&self) -> u8 {
                222
            }
            fn digest(&self, _owner: &Name, _key: &Dnskey<'_>) -> Vec<u8> {
                vec![1, 2, 3]
            }
        }
        let key = Dnskey::parse(&[1, 0, 3, 8, 4]).unwrap();
        let ds = Ds {
            key_tag: key.key_tag().unwrap(),
            algorithm: 8,
            digest_type: 222,
            digest: &[1, 2, 3],
        };
        let backend: &dyn DsDigest = &External;
        assert!(ds.matches_dnskey(backend, &Name::root(), &key));
    }

    #[cfg(all(feature = "dnssec-ring", feature = "dnssec-sha2"))]
    #[test]
    fn authenticated_ds_requires_matching_key_and_current_dnskey_rrsig() {
        use crate::RecordType;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let pair = Ed25519KeyPair::from_seed_unchecked(&[13; 32]).unwrap();
        let mut wire = vec![1, 1, 3, 15];
        wire.extend_from_slice(pair.public_key().as_ref());
        let key = Dnskey::parse(&wire).unwrap();
        let zone = Name::from_ascii("example.com").unwrap();
        let digest = crypto::Sha256Digest.digest(&zone, &key);
        let ds = Ds {
            key_tag: key.key_tag().unwrap(),
            algorithm: 15,
            digest_type: 2,
            digest: &digest,
        };
        let rr = ResourceRecord {
            name: zone.clone(),
            rtype: RecordType::Other(48),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 48,
                data: wire.clone(),
            },
        };
        let mut sig = Rrsig {
            type_covered: 48,
            algorithm: 15,
            labels: 2,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: key.key_tag().unwrap(),
            signer: zone.clone(),
            signature: &[],
        };
        let data = sig
            .signed_data(&zone, Class::In, std::slice::from_ref(&rr))
            .unwrap();
        let signed = pair.sign(&data);
        sig.signature = signed.as_ref();
        let check = |anchor: &Ds<'_>, records: &[ResourceRecord], now| {
            anchor.verify_dnskey_rrset(
                &crypto::Sha256Digest,
                &crypto::RingVerifier,
                &zone,
                records,
                &sig,
                now,
            )
        };
        assert_eq!(check(&ds, std::slice::from_ref(&rr), 10), Ok(()));
        assert_eq!(
            check(&ds, std::slice::from_ref(&rr), 21),
            Err(DnskeyAuthenticationError::Signature(
                SignatureError::OutsideValidityPeriod
            ))
        );
        assert_eq!(
            check(
                &Ds {
                    digest_type: 4,
                    ..ds
                },
                std::slice::from_ref(&rr),
                10
            ),
            Err(DnskeyAuthenticationError::UnsupportedDigest)
        );
        assert_eq!(
            check(
                &Ds {
                    digest: &[0; 32],
                    ..ds
                },
                std::slice::from_ref(&rr),
                10
            ),
            Err(DnskeyAuthenticationError::NoMatchingKey)
        );
        let mut added = rr.clone();
        if let RData::Unknown { data, .. } = &mut added.rdata {
            data.push(0);
        }
        assert_eq!(
            check(&ds, &[rr, added], 10),
            Err(DnskeyAuthenticationError::Signature(
                SignatureError::Crypto(CryptoError::InvalidSignature)
            ))
        );
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
    fn rrsig_time_window_handles_boundaries_wrap_and_ambiguity() {
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 0,
            original_ttl: 1,
            expiration: 20,
            inception: 10,
            key_tag: 0,
            signer: Name::root(),
            signature: &[],
        };
        for now in [10, 11, 19, 20] {
            assert!(sig.valid_at(now));
        }
        for now in [9, 21] {
            assert!(!sig.valid_at(now));
        }
        sig.inception = u32::MAX - 2;
        sig.expiration = 2;
        for now in [u32::MAX - 2, u32::MAX, 0, 2] {
            assert!(sig.valid_at(now));
        }
        for now in [u32::MAX - 3, 3] {
            assert!(!sig.valid_at(now));
        }
        sig.inception = 0;
        sig.expiration = 1 << 31;
        assert!(!sig.valid_at(0));
        sig.expiration = 0;
        assert!(sig.valid_at(0));
        assert!(!sig.valid_at(1));
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

    #[test]
    fn signature_verifier_can_be_supplied_as_a_trait_object() {
        use crate::RecordType;
        struct External;
        impl SignatureVerifier for External {
            fn verify(
                &self,
                algorithm: u8,
                key: &[u8],
                data: &[u8],
                sig: &[u8],
            ) -> Result<(), CryptoError> {
                assert_eq!((algorithm, key, sig), (222, &[7, 8][..], &[9][..]));
                assert!(!data.is_empty());
                Ok(())
            }
        }
        let key_wire = [1, 0, 3, 222, 7, 8];
        let key = Dnskey::parse(&key_wire).unwrap();
        let owner = Name::from_ascii("example.com").unwrap();
        let rr = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 1,
            rdata: RData::A(std::net::Ipv4Addr::LOCALHOST),
        };
        let sig = Rrsig {
            type_covered: 1,
            algorithm: 222,
            labels: 2,
            original_ttl: 1,
            expiration: 2,
            inception: 1,
            key_tag: key.key_tag().unwrap(),
            signer: owner.clone(),
            signature: &[9],
        };
        let verifier: &dyn SignatureVerifier = &External;
        assert_eq!(
            sig.verify_at(verifier, &owner, &key, &owner, Class::In, &[rr], 1),
            Ok(())
        );
    }

    #[cfg(feature = "dnssec-ring")]
    #[test]
    fn verifies_ed25519_rrset_and_rejects_tampering() {
        use crate::RecordType;
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let mut key_wire = vec![1, 1, 3, 15];
        key_wire.extend_from_slice(pair.public_key().as_ref());
        let key = Dnskey::parse(&key_wire).unwrap();
        let owner = Name::from_ascii("www.example.com").unwrap();
        let signer = Name::from_ascii("example.com").unwrap();
        let rr = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 1,
            rdata: RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        };
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 3,
            original_ttl: 300,
            expiration: 10,
            inception: 1,
            key_tag: key.key_tag().unwrap(),
            signer: signer.clone(),
            signature: &[],
        };
        let signed = sig
            .signed_data(&owner, Class::In, std::slice::from_ref(&rr))
            .unwrap();
        let signature = pair.sign(&signed);
        sig.signature = signature.as_ref();
        assert_eq!(
            sig.verify(
                &crypto::RingVerifier,
                &signer,
                &key,
                &owner,
                Class::In,
                std::slice::from_ref(&rr)
            ),
            Ok(())
        );
        assert_eq!(
            sig.verify_at(
                &crypto::RingVerifier,
                &signer,
                &key,
                &owner,
                Class::In,
                std::slice::from_ref(&rr),
                10
            ),
            Ok(())
        );
        assert_eq!(
            sig.verify_at(
                &crypto::RingVerifier,
                &signer,
                &key,
                &owner,
                Class::In,
                std::slice::from_ref(&rr),
                11
            ),
            Err(SignatureError::OutsideValidityPeriod)
        );
        let mut tampered = rr.clone();
        tampered.rdata = RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(
            sig.verify(
                &crypto::RingVerifier,
                &signer,
                &key,
                &owner,
                Class::In,
                &[tampered]
            ),
            Err(SignatureError::Crypto(CryptoError::InvalidSignature))
        );
        assert_eq!(
            sig.verify(
                &crypto::RingVerifier,
                &owner,
                &key,
                &owner,
                Class::In,
                &[rr]
            ),
            Err(SignatureError::InvalidKey)
        );
    }

    #[cfg(feature = "dnssec-ring")]
    #[test]
    fn verifies_rfc_8080_ed25519_mx_example() {
        use crate::RecordType;
        let mut key_wire = vec![1, 1, 3, 15];
        key_wire.extend_from_slice(&[
            151, 77, 150, 162, 45, 34, 75, 192, 26, 219, 145, 80, 145, 71, 125, 68, 204, 217, 28,
            154, 65, 161, 20, 48, 1, 1, 23, 213, 44, 89, 36, 14,
        ]);
        let key = Dnskey::parse(&key_wire).unwrap();
        // RFC 8080 verified erratum 4935 corrects the original signature.
        let signature = [
            160, 191, 100, 172, 155, 167, 239, 23, 193, 56, 133, 156, 24, 120, 187, 153, 168, 57,
            254, 23, 89, 172, 165, 176, 215, 152, 207, 26, 177, 233, 141, 7, 145, 2, 244, 221, 179,
            54, 143, 15, 228, 11, 179, 119, 241, 240, 14, 12, 221, 237, 183, 153, 22, 125, 86, 182,
            233, 50, 120, 48, 114, 186, 141, 2,
        ];
        let owner = Name::from_ascii("example.com").unwrap();
        let rr = ResourceRecord {
            name: owner.clone(),
            rtype: RecordType::Mx,
            class: Class::In,
            ttl: 3600,
            rdata: RData::Mx {
                preference: 10,
                exchange: Name::from_ascii("mail.example.com").unwrap(),
            },
        };
        let sig = Rrsig {
            type_covered: 15,
            algorithm: 15,
            labels: 2,
            original_ttl: 3600,
            expiration: 1440021600,
            inception: 1438207200,
            key_tag: 3613,
            signer: owner.clone(),
            signature: &signature,
        };
        assert_eq!(
            sig.verify(
                &crypto::RingVerifier,
                &owner,
                &key,
                &owner,
                Class::In,
                &[rr]
            ),
            Ok(())
        );
    }
}
