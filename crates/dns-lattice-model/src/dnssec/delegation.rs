//! Low-level verification of a DS RRset using a previously authenticated key.

use crate::{Name, RData, ResourceRecord};

use super::{
    Dnskey, DnskeyAuthenticationError, Ds, Rrsig, SignatureError,
    crypto::{DsDigest, SignatureVerifier},
};

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

/// One caller-supplied, positive DS-to-DNSKEY delegation proof.
///
/// All records are untrusted inputs. The parent key and the fact of the
/// delegation must be established independently by the caller.
#[derive(Clone, Copy)]
pub struct DelegationProof<'a> {
    /// The DNS zone that signed the DS RRset.
    pub parent_zone: &'a Name,
    /// The already authenticated parent-zone key used for that signature.
    pub parent_key: &'a Dnskey<'a>,
    /// The delegated child zone and DS/DNSKEY owner.
    pub child_zone: &'a Name,
    /// DS records signed by the parent.
    pub ds_rrset: &'a [ResourceRecord],
    /// One parent signature over the DS RRset.
    pub ds_signature: &'a Rrsig<'a>,
    /// Child DNSKEY records signed by a key matching an authenticated DS.
    pub dnskey_rrset: &'a [ResourceRecord],
    /// One child signature over the DNSKEY RRset.
    pub dnskey_signature: &'a Rrsig<'a>,
}

/// Failure in a single positive DNSSEC delegation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    /// Parent verification of the DS RRset failed.
    Parent(DsAuthenticationError),
    /// Child DNSKEY and parent DS records use different DNS classes.
    ClassMismatch,
    /// No authenticated DS record uses the selected digest implementation.
    NoSupportedDs,
    /// None of the selected DS records authenticated the child DNSKEY RRset.
    Child(DnskeyAuthenticationError),
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSSEC delegation check failed: {self:?}")
    }
}
impl std::error::Error for DelegationError {}

impl DelegationProof<'_> {
    /// Verifies one positive delegation against an authenticated parent key.
    ///
    /// Exactly one DS digest algorithm, selected by the caller, is attempted;
    /// this function does not choose or downgrade digest policy. It checks
    /// only the supplied signatures and does not perform lookups, prove that
    /// this is an actual zone cut, process an absent DS, or validate answers.
    pub fn verify(
        &self,
        verifier: &(impl SignatureVerifier + ?Sized),
        digest: &(impl DsDigest + ?Sized),
        now: u32,
    ) -> Result<(), DelegationError> {
        verify_ds_rrset(
            verifier,
            self.parent_zone,
            self.parent_key,
            self.child_zone,
            self.ds_rrset,
            self.ds_signature,
            now,
        )
        .map_err(DelegationError::Parent)?;
        if self
            .dnskey_rrset
            .first()
            .is_some_and(|rr| rr.class != self.ds_rrset[0].class)
        {
            return Err(DelegationError::ClassMismatch);
        }
        let mut error = None;
        for rr in self.ds_rrset {
            let RData::Unknown { rtype: 43, data } = &rr.rdata else {
                continue;
            };
            let Some(ds) = Ds::parse(data) else { continue };
            if ds.digest_type != digest.digest_type() {
                continue;
            }
            match ds.verify_dnskey_rrset(
                digest,
                verifier,
                self.child_zone,
                self.dnskey_rrset,
                self.dnskey_signature,
                now,
            ) {
                Ok(()) => return Ok(()),
                Err(reason) => error = Some(reason),
            }
        }
        Err(error.map_or(DelegationError::NoSupportedDs, DelegationError::Child))
    }
}

/// Failure while checking a sequence of positive DNSSEC delegations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// A chain must contain at least one delegation.
    Empty,
    /// Each delegation must have exactly one caller-selected digest backend.
    DigestCount,
    /// A step does not continue from the previously authenticated zone.
    ParentZone {
        /// Zero-based delegation index.
        step: usize,
    },
    /// A step's parent key is not the trust anchor or a previously authenticated DNSKEY.
    ParentKey {
        /// Zero-based delegation index.
        step: usize,
    },
    /// A step's DS RRset is in a different class than the trust anchor.
    Class {
        /// Zero-based delegation index.
        step: usize,
    },
    /// Verification of one delegation failed.
    Delegation {
        /// Zero-based delegation index.
        step: usize,
        /// Why the delegation failed.
        error: DelegationError,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSSEC positive chain check failed: {self:?}")
    }
}
impl std::error::Error for ChainError {}

/// Verifies a supplied sequence of positive delegations from a trusted DNSKEY.
///
/// Each step must continue the previous zone and use a parent key present in
/// the DNSKEY RRset authenticated by the preceding step. `anchor_zone`,
/// `anchor_key`, and `anchor_class` are trusted inputs. Digest implementations
/// are chosen explicitly, one per step, without automatic fallback.
///
/// The caller must establish that each step is an actual zone cut. This does
/// not discover records, prove unsigned delegations or authenticate the final
/// answer. It does not implement trust-anchor maintenance or rollover policy.
#[allow(clippy::too_many_arguments)]
pub fn verify_positive_chain(
    anchor_zone: &Name,
    anchor_key: &Dnskey<'_>,
    anchor_class: crate::Class,
    proofs: &[DelegationProof<'_>],
    digests: &[&dyn DsDigest],
    verifier: &(impl SignatureVerifier + ?Sized),
    now: u32,
) -> Result<(), ChainError> {
    if proofs.is_empty() {
        return Err(ChainError::Empty);
    }
    if proofs.len() != digests.len() {
        return Err(ChainError::DigestCount);
    }
    let mut current_zone = anchor_zone;
    let mut prior_keys: Option<&[ResourceRecord]> = None;
    for (step, (proof, digest)) in proofs.iter().zip(digests).enumerate() {
        if proof.parent_zone != current_zone {
            return Err(ChainError::ParentZone { step });
        }
        let trusted_key = match prior_keys {
            None => proof.parent_key.wire == anchor_key.wire,
            Some(keys) => keys.iter().any(|rr| {
                matches!(&rr.rdata, RData::Unknown { rtype: 48, data } if data == proof.parent_key.wire)
            }),
        };
        if !trusted_key {
            return Err(ChainError::ParentKey { step });
        }
        if proof
            .ds_rrset
            .first()
            .is_some_and(|rr| rr.class != anchor_class)
        {
            return Err(ChainError::Class { step });
        }
        proof
            .verify(verifier, *digest, now)
            .map_err(|error| ChainError::Delegation { step, error })?;
        current_zone = proof.child_zone;
        prior_keys = Some(proof.dnskey_rrset);
    }
    Ok(())
}

#[cfg(all(test, feature = "dnssec-ring"))]
mod tests {
    use super::*;
    use crate::dnssec::crypto::{CryptoError, RingVerifier};
    use crate::{Class, RData, RecordType};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[cfg(feature = "dnssec-sha2")]
    #[test]
    fn positive_delegation_requires_both_authenticated_rrsets() {
        use crate::dnssec::crypto::{DsDigest, Sha256Digest, Sha384Digest};
        let parent_pair = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let child_pair = Ed25519KeyPair::from_seed_unchecked(&[32; 32]).unwrap();
        let mut parent_wire = vec![1, 1, 3, 15];
        parent_wire.extend_from_slice(parent_pair.public_key().as_ref());
        let parent_key = Dnskey::parse(&parent_wire).unwrap();
        let mut child_wire = vec![1, 1, 3, 15];
        child_wire.extend_from_slice(child_pair.public_key().as_ref());
        let child_key = Dnskey::parse(&child_wire).unwrap();
        let parent = Name::from_ascii("example.com").unwrap();
        let child = Name::from_ascii("child.example.com").unwrap();
        let mut ds_wire = child_key.key_tag().unwrap().to_be_bytes().to_vec();
        ds_wire.extend_from_slice(&[15, 2]);
        ds_wire.extend(Sha256Digest.digest(&child, &child_key));
        let ds = ResourceRecord {
            name: child.clone(),
            rtype: RecordType::Other(43),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 43,
                data: ds_wire,
            },
        };
        let child_rr = ResourceRecord {
            name: child.clone(),
            rtype: RecordType::Other(48),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 48,
                data: child_wire.clone(),
            },
        };
        let mut ds_sig = Rrsig {
            type_covered: 43,
            algorithm: 15,
            labels: 3,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: parent_key.key_tag().unwrap(),
            signer: parent.clone(),
            signature: &[],
        };
        let mut key_sig = Rrsig {
            type_covered: 48,
            algorithm: 15,
            labels: 3,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: child_key.key_tag().unwrap(),
            signer: child.clone(),
            signature: &[],
        };
        let signed_ds = parent_pair.sign(
            &ds_sig
                .signed_data(&child, Class::In, std::slice::from_ref(&ds))
                .unwrap(),
        );
        let signed_key = child_pair.sign(
            &key_sig
                .signed_data(&child, Class::In, std::slice::from_ref(&child_rr))
                .unwrap(),
        );
        ds_sig.signature = signed_ds.as_ref();
        key_sig.signature = signed_key.as_ref();
        let ds_set = [ds];
        let key_set = [child_rr];
        let proof = |keys| DelegationProof {
            parent_zone: &parent,
            parent_key: &parent_key,
            child_zone: &child,
            ds_rrset: &ds_set,
            ds_signature: &ds_sig,
            dnskey_rrset: keys,
            dnskey_signature: &key_sig,
        };
        assert_eq!(
            proof(&key_set).verify(&RingVerifier, &Sha256Digest, 10),
            Ok(())
        );
        let grand_pair = Ed25519KeyPair::from_seed_unchecked(&[33; 32]).unwrap();
        let mut grand_wire = vec![1, 1, 3, 15];
        grand_wire.extend_from_slice(grand_pair.public_key().as_ref());
        let grand_key = Dnskey::parse(&grand_wire).unwrap();
        let grand = Name::from_ascii("sub.child.example.com").unwrap();
        let mut grand_ds_wire = grand_key.key_tag().unwrap().to_be_bytes().to_vec();
        grand_ds_wire.extend_from_slice(&[15, 2]);
        grand_ds_wire.extend(Sha256Digest.digest(&grand, &grand_key));
        let grand_ds = [ResourceRecord {
            name: grand.clone(),
            rtype: RecordType::Other(43),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 43,
                data: grand_ds_wire,
            },
        }];
        let grand_keys = [ResourceRecord {
            name: grand.clone(),
            rtype: RecordType::Other(48),
            class: Class::In,
            ttl: 100,
            rdata: RData::Unknown {
                rtype: 48,
                data: grand_wire.clone(),
            },
        }];
        let mut grand_ds_sig = Rrsig {
            type_covered: 43,
            algorithm: 15,
            labels: 4,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: child_key.key_tag().unwrap(),
            signer: child.clone(),
            signature: &[],
        };
        let mut grand_key_sig = Rrsig {
            type_covered: 48,
            algorithm: 15,
            labels: 4,
            original_ttl: 100,
            expiration: 20,
            inception: 10,
            key_tag: grand_key.key_tag().unwrap(),
            signer: grand.clone(),
            signature: &[],
        };
        let grand_ds_bytes = child_pair.sign(
            &grand_ds_sig
                .signed_data(&grand, Class::In, &grand_ds)
                .unwrap(),
        );
        let grand_key_bytes = grand_pair.sign(
            &grand_key_sig
                .signed_data(&grand, Class::In, &grand_keys)
                .unwrap(),
        );
        grand_ds_sig.signature = grand_ds_bytes.as_ref();
        grand_key_sig.signature = grand_key_bytes.as_ref();
        let second = DelegationProof {
            parent_zone: &child,
            parent_key: &child_key,
            child_zone: &grand,
            ds_rrset: &grand_ds,
            ds_signature: &grand_ds_sig,
            dnskey_rrset: &grand_keys,
            dnskey_signature: &grand_key_sig,
        };
        let chain = [proof(&key_set), second];
        let digests: [&dyn DsDigest; 2] = [&Sha256Digest, &Sha256Digest];
        assert_eq!(
            verify_positive_chain(
                &parent,
                &parent_key,
                Class::In,
                &chain,
                &digests,
                &RingVerifier,
                10
            ),
            Ok(())
        );
        assert_eq!(
            verify_positive_chain(
                &parent,
                &child_key,
                Class::In,
                &chain,
                &digests,
                &RingVerifier,
                10
            ),
            Err(ChainError::ParentKey { step: 0 })
        );
        assert_eq!(
            verify_positive_chain(
                &parent,
                &parent_key,
                Class::Ch,
                &chain,
                &digests,
                &RingVerifier,
                10
            ),
            Err(ChainError::Class { step: 0 })
        );
        assert_eq!(
            verify_positive_chain(
                &parent,
                &parent_key,
                Class::In,
                &chain,
                &digests[..1],
                &RingVerifier,
                10
            ),
            Err(ChainError::DigestCount)
        );
        let impostor = DelegationProof {
            parent_key: &parent_key,
            ..chain[1]
        };
        let broken = [proof(&key_set), impostor];
        assert_eq!(
            verify_positive_chain(
                &parent,
                &parent_key,
                Class::In,
                &broken,
                &digests,
                &RingVerifier,
                10
            ),
            Err(ChainError::ParentKey { step: 1 })
        );
        let wrong_zone = DelegationProof {
            parent_zone: &grand,
            ..chain[1]
        };
        let broken_zone = [proof(&key_set), wrong_zone];
        assert_eq!(
            verify_positive_chain(
                &parent,
                &parent_key,
                Class::In,
                &broken_zone,
                &digests,
                &RingVerifier,
                10
            ),
            Err(ChainError::ParentZone { step: 1 })
        );
        assert_eq!(
            verify_positive_chain(&parent, &parent_key, Class::In, &[], &[], &RingVerifier, 10),
            Err(ChainError::Empty)
        );
        assert_eq!(
            proof(&key_set).verify(&RingVerifier, &Sha384Digest, 10),
            Err(DelegationError::NoSupportedDs)
        );
        assert!(matches!(
            proof(&key_set).verify(&RingVerifier, &Sha256Digest, 21),
            Err(DelegationError::Parent(DsAuthenticationError::Signature(
                SignatureError::OutsideValidityPeriod
            )))
        ));
        let mut changed_ds = [ds_set[0].clone()];
        if let RData::Unknown { data, .. } = &mut changed_ds[0].rdata {
            data.push(0);
        }
        let forged_ds = DelegationProof {
            ds_rrset: &changed_ds,
            ..proof(&key_set)
        };
        assert!(matches!(
            forged_ds.verify(&RingVerifier, &Sha256Digest, 10),
            Err(DelegationError::Parent(DsAuthenticationError::Signature(
                SignatureError::Crypto(CryptoError::InvalidSignature)
            )))
        ));
        let mut bad_key_sig = key_sig.clone();
        bad_key_sig.signature = &[0; 64];
        let forged_key_sig = DelegationProof {
            dnskey_signature: &bad_key_sig,
            ..proof(&key_set)
        };
        assert!(matches!(
            forged_key_sig.verify(&RingVerifier, &Sha256Digest, 10),
            Err(DelegationError::Child(
                DnskeyAuthenticationError::Signature(SignatureError::Crypto(
                    CryptoError::InvalidSignature
                ))
            ))
        ));
        let mut wrong_class = [key_set[0].clone()];
        wrong_class[0].class = Class::Ch;
        assert_eq!(
            proof(&wrong_class).verify(&RingVerifier, &Sha256Digest, 10),
            Err(DelegationError::ClassMismatch)
        );
        let mut changed = [key_set[0].clone()];
        if let RData::Unknown { data, .. } = &mut changed[0].rdata {
            data.push(0);
        }
        assert!(matches!(
            proof(&changed).verify(&RingVerifier, &Sha256Digest, 10),
            Err(DelegationError::Child(
                DnskeyAuthenticationError::NoMatchingKey
            ))
        ));
    }

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
