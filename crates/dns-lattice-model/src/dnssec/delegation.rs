//! Low-level verification of a DS RRset using a previously authenticated key.

use crate::{Name, ResourceRecord};

use super::{Dnskey, Rrsig, SignatureError, crypto::SignatureVerifier};

/// Failure to verify the supplied DS RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsAuthenticationError {
    /// The proposed child is not strictly below the parent zone.
    InvalidDelegation,
    /// The RRset is empty, has the wrong type, or uses wildcard expansion.
    InvalidRrset,
    /// The RRSIG was not made by the claimed parent zone.
    WrongSigner,
    /// The RRSIG, key, time, canonical data, or signature check failed.
    Signature(SignatureError),
}

impl std::fmt::Display for DsAuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DS RRset authentication failed: {self:?}")
    }
}
impl std::error::Error for DsAuthenticationError {}

/// Verifies a DS RRset using a key already authenticated for `parent_zone`.
///
/// The caller must authenticate the parent DNSKEY in the DS RRset's class and
/// establish that `child` is an actual delegation owned by that parent. This function checks a single
/// RRSIG and confirms its signer, time, key, and covered RRset; it does not
/// perform DNS lookups, select a DS digest, validate absence of DS, handle
/// trust-anchor rollover, or build a chain. Passing an untrusted key or an
/// untrusted cryptographic backend does not establish DNSSEC trust.
#[allow(clippy::too_many_arguments)]
pub fn verify_ds_rrset(
    verifier: &(impl SignatureVerifier + ?Sized),
    parent_zone: &Name,
    parent_key: &Dnskey<'_>,
    child: &Name,
    rrset: &[ResourceRecord],
    signature: &Rrsig<'_>,
    now: u32,
) -> Result<(), DsAuthenticationError> {
    if child == parent_zone || !child.ends_with(parent_zone) {
        return Err(DsAuthenticationError::InvalidDelegation);
    }
    if rrset.is_empty()
        || signature.type_covered != 43
        || usize::from(signature.labels) != child.label_count()
    {
        return Err(DsAuthenticationError::InvalidRrset);
    }
    if signature.signer != *parent_zone {
        return Err(DsAuthenticationError::WrongSigner);
    }
    signature
        .verify_at(
            verifier,
            parent_zone,
            parent_key,
            child,
            rrset[0].class,
            rrset,
            now,
        )
        .map_err(DsAuthenticationError::Signature)
}

#[cfg(all(test, feature = "dnssec-ring"))]
mod tests {
    use super::*;
    use crate::dnssec::crypto::{CryptoError, RingVerifier};
    use crate::{Class, RData, RecordType};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn signed_ds_requires_parent_key_time_owner_and_unchanged_records() {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let mut wire = vec![1, 1, 3, 15];
        wire.extend_from_slice(pair.public_key().as_ref());
        let key = Dnskey::parse(&wire).unwrap();
        let parent = Name::from_ascii("example.com").unwrap();
        let child = Name::from_ascii("child.example.com").unwrap();
        let mut ds = ResourceRecord {
            name: child.clone(),
            rtype: RecordType::Other(43),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 43,
                data: vec![0, 1, 15, 2, 42],
            },
        };
        let mut sig = Rrsig {
            type_covered: 43,
            algorithm: 15,
            labels: 3,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: key.key_tag().unwrap(),
            signer: parent.clone(),
            signature: &[],
        };
        let data = sig
            .signed_data(&child, Class::In, std::slice::from_ref(&ds))
            .unwrap();
        let signed = pair.sign(&data);
        sig.signature = signed.as_ref();
        assert_eq!(
            verify_ds_rrset(
                &RingVerifier,
                &parent,
                &key,
                &child,
                std::slice::from_ref(&ds),
                &sig,
                10
            ),
            Ok(())
        );
        assert_eq!(
            verify_ds_rrset(
                &RingVerifier,
                &parent,
                &key,
                &child,
                std::slice::from_ref(&ds),
                &sig,
                21
            ),
            Err(DsAuthenticationError::Signature(
                SignatureError::OutsideValidityPeriod
            ))
        );
        assert_eq!(
            verify_ds_rrset(
                &RingVerifier,
                &parent,
                &key,
                &parent,
                std::slice::from_ref(&ds),
                &sig,
                10
            ),
            Err(DsAuthenticationError::InvalidDelegation)
        );
        let mut wrong = sig.clone();
        wrong.signer = child.clone();
        assert_eq!(
            verify_ds_rrset(
                &RingVerifier,
                &parent,
                &key,
                &child,
                std::slice::from_ref(&ds),
                &wrong,
                10
            ),
            Err(DsAuthenticationError::WrongSigner)
        );
        wrong = sig.clone();
        wrong.labels -= 1;
        assert_eq!(
            verify_ds_rrset(
                &RingVerifier,
                &parent,
                &key,
                &child,
                std::slice::from_ref(&ds),
                &wrong,
                10
            ),
            Err(DsAuthenticationError::InvalidRrset)
        );
        if let RData::Unknown { data, .. } = &mut ds.rdata {
            data.push(1);
        }
        assert_eq!(
            verify_ds_rrset(&RingVerifier, &parent, &key, &child, &[ds], &sig, 10),
            Err(DsAuthenticationError::Signature(SignatureError::Crypto(
                CryptoError::InvalidSignature
            )))
        );
    }
}
