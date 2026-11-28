//! DNSSEC wire-record helpers. These helpers do not validate DNS answers.
//!
//! DNSKEY and DS records are still represented by `RData::Unknown` in the
//! message model. These borrowed views allow callers to inspect their RDATA
//! without altering the existing wire representation or allocating.

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
}
