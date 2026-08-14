//! The DNS message envelope: header, question, resource records, and the
//! full message with wire encode/decode.

use dns_lattice_core::{Error, Result};

use super::record::{Class, RData, RecordType};

/// An owned, case-preserving DNS domain name.
///
/// Equality and hashing compare ASCII-lowercased labels (DNS names are
/// case-insensitive per RFC 1035 §2.3.3), but the original case is kept
/// internally so encoding round-trips byte-for-byte.
#[derive(Debug, Clone)]
pub struct Name(pub(crate) Vec<Vec<u8>>);

impl Name {
    /// The root name (zero labels).
    pub fn root() -> Self {
        Name(Vec::new())
    }

    /// Parses a name from its ASCII presentation form (e.g.
    /// `"example.com"` or `"example.com."`).
    ///
    /// A trailing dot is accepted and stripped. Empty labels (consecutive
    /// or leading dots), labels over 63 bytes, non-ASCII bytes, or a total
    /// encoded length over 255 bytes are rejected.
    pub fn from_ascii(s: &str) -> Result<Self> {
        if s.is_empty() || s == "." {
            return Ok(Name::root());
        }
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        if trimmed.is_empty() {
            return Err(Error::InvalidName);
        }
        let mut labels = Vec::new();
        for part in trimmed.split('.') {
            if part.is_empty() {
                return Err(Error::InvalidName);
            }
            if !part.is_ascii() {
                return Err(Error::InvalidName);
            }
            if part.len() > 63 {
                return Err(Error::LabelTooLong { offset: 0 });
            }
            labels.push(part.as_bytes().to_vec());
        }
        let name = Name(labels);
        name.check_total_length()?;
        Ok(name)
    }

    /// Iterates over this name's labels, most specific first.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.0.iter().map(|label| label.as_slice())
    }

    /// Whether this is the root name (zero labels).
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    fn check_total_length(&self) -> Result<()> {
        let total: usize = self.0.iter().map(|label| label.len() + 1).sum::<usize>() + 1;
        if total > 255 {
            return Err(Error::NameTooLong);
        }
        Ok(())
    }

    fn lowercased_labels(&self) -> Vec<Vec<u8>> {
        self.0
            .iter()
            .map(|label| label.to_ascii_lowercase())
            .collect()
    }

    /// The number of labels in this name (0 for the root name).
    pub(crate) fn label_count(&self) -> usize {
        self.0.len()
    }

    /// Whether this name's rightmost labels equal `suffix` (case-insensitive).
    /// A name is always its own suffix.
    pub(crate) fn ends_with(&self, suffix: &Name) -> bool {
        if suffix.0.len() > self.0.len() {
            return false;
        }
        let offset = self.0.len() - suffix.0.len();
        self.0[offset..]
            .iter()
            .zip(suffix.0.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.lowercased_labels() == other.lowercased_labels()
    }
}

impl Eq for Name {}

impl std::hash::Hash for Name {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.lowercased_labels().hash(state);
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for label in &self.0 {
            write!(f, "{}.", String::from_utf8_lossy(label))?;
        }
        Ok(())
    }
}

/// A DNS message opcode (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A standard query.
    Query,
    /// An inverse query (obsolete, RFC 3425).
    IQuery,
    /// A server status request.
    Status,
    /// A zone change notification (RFC 1996).
    Notify,
    /// A dynamic update (RFC 2136).
    Update,
    /// Any opcode value not enumerated above (0-15).
    Other(u8),
}

impl Opcode {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            other => Opcode::Other(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Other(value) => value & 0x0F,
        }
    }
}

/// A DNS message response code (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    /// No error.
    NoError,
    /// Format error.
    FormErr,
    /// Server failure.
    ServFail,
    /// Non-existent domain.
    NxDomain,
    /// Not implemented.
    NotImp,
    /// Query refused.
    Refused,
    /// Any response code value not enumerated above (0-15).
    Other(u8),
}

impl Rcode {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            other => Rcode::Other(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::Other(value) => value & 0x0F,
        }
    }
}

/// A DNS message header (RFC 1035 §4.1.1).
///
/// Section counts are not stored here: [`Message::encode`] derives them
/// from its question/answer/authority/additional vector lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The query identifier, echoed between a query and its response.
    pub id: u16,
    /// Whether this message is a response (`true`) or a query (`false`).
    pub qr: bool,
    /// The kind of query this message performs.
    pub opcode: Opcode,
    /// Whether the responding server is authoritative for the queried
    /// name.
    pub authoritative: bool,
    /// Whether this message was truncated for the transport it was sent
    /// over.
    pub truncated: bool,
    /// Whether the client requests recursive resolution.
    pub recursion_desired: bool,
    /// Whether the server supports recursive resolution.
    pub recursion_available: bool,
    /// The response status.
    pub rcode: Rcode,
}

/// A DNS question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The queried name.
    pub name: Name,
    /// The queried record type.
    pub qtype: RecordType,
    /// The queried record class.
    pub qclass: Class,
}

/// A DNS resource record (RFC 1035 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// The record's owner name.
    pub name: Name,
    /// The record's type; also determines `rdata`'s variant.
    pub rtype: RecordType,
    /// The record's class.
    pub class: Class,
    /// Seconds this record may be cached, clamped to zero if the wire
    /// value read as negative under RFC 2181's signed framing.
    pub ttl: u32,
    /// The record's type-specific data.
    pub rdata: RData,
}

/// A complete DNS message (RFC 1035 §4.1): header plus the four sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message header.
    pub header: Header,
    /// The question section.
    pub questions: Vec<Question>,
    /// The answer section.
    pub answers: Vec<ResourceRecord>,
    /// The authority section.
    pub authorities: Vec<ResourceRecord>,
    /// The additional section.
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Decodes a message from its wire representation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let (header, qc, ac, nsc, arc) = decode_header(bytes, &mut pos)?;

        let mut questions = Vec::with_capacity(qc as usize);
        for _ in 0..qc {
            questions.push(decode_question(bytes, &mut pos)?);
        }
        let mut answers = Vec::with_capacity(ac as usize);
        for _ in 0..ac {
            answers.push(decode_rr(bytes, &mut pos)?);
        }
        let mut authorities = Vec::with_capacity(nsc as usize);
        for _ in 0..nsc {
            authorities.push(decode_rr(bytes, &mut pos)?);
        }
        let mut additionals = Vec::with_capacity(arc as usize);
        for _ in 0..arc {
            additionals.push(decode_rr(bytes, &mut pos)?);
        }

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Encodes this message to a freshly allocated buffer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// Encodes this message into an existing buffer, appending to it.
    pub fn encode_into(&self, buf: &mut Vec<u8>) -> Result<()> {
        let qc = to_u16_count(self.questions.len())?;
        let ac = to_u16_count(self.answers.len())?;
        let nsc = to_u16_count(self.authorities.len())?;
        let arc = to_u16_count(self.additionals.len())?;

        encode_header(&self.header, (qc, ac, nsc, arc), buf);
        for question in &self.questions {
            encode_question(question, buf)?;
        }
        for rr in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            encode_rr(rr, buf)?;
        }

        if buf.len() > u16::MAX as usize {
            return Err(Error::MessageTooLong);
        }
        Ok(())
    }
}

fn to_u16_count(len: usize) -> Result<u16> {
    u16::try_from(len).map_err(|_| Error::MessageTooLong)
}

fn decode_header(buf: &[u8], pos: &mut usize) -> Result<(Header, u16, u16, u16, u16)> {
    let id = read_u16(buf, pos)?;
    let flags = read_u16(buf, pos)?;
    let qdcount = read_u16(buf, pos)?;
    let ancount = read_u16(buf, pos)?;
    let nscount = read_u16(buf, pos)?;
    let arcount = read_u16(buf, pos)?;

    let header = Header {
        id,
        qr: flags & 0x8000 != 0,
        opcode: Opcode::from_u8(((flags >> 11) & 0x0F) as u8),
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        rcode: Rcode::from_u8((flags & 0x0F) as u8),
    };
    Ok((header, qdcount, ancount, nscount, arcount))
}

fn encode_header(header: &Header, counts: (u16, u16, u16, u16), buf: &mut Vec<u8>) {
    let mut flags: u16 = 0;
    if header.qr {
        flags |= 0x8000;
    }
    flags |= (header.opcode.to_u8() as u16) << 11;
    if header.authoritative {
        flags |= 0x0400;
    }
    if header.truncated {
        flags |= 0x0200;
    }
    if header.recursion_desired {
        flags |= 0x0100;
    }
    if header.recursion_available {
        flags |= 0x0080;
    }
    flags |= header.rcode.to_u8() as u16;

    write_u16(buf, header.id);
    write_u16(buf, flags);
    write_u16(buf, counts.0);
    write_u16(buf, counts.1);
    write_u16(buf, counts.2);
    write_u16(buf, counts.3);
}

fn decode_question(buf: &[u8], pos: &mut usize) -> Result<Question> {
    let name = decode_name(buf, pos)?;
    let qtype = RecordType::from_u16(read_u16(buf, pos)?);
    let qclass = Class::from_u16(read_u16(buf, pos)?)?;
    Ok(Question {
        name,
        qtype,
        qclass,
    })
}

fn encode_question(question: &Question, buf: &mut Vec<u8>) -> Result<()> {
    encode_name(&question.name, buf)?;
    write_u16(buf, question.qtype.to_u16());
    write_u16(buf, question.qclass.to_u16());
    Ok(())
}

fn decode_rr(buf: &[u8], pos: &mut usize) -> Result<ResourceRecord> {
    let name = decode_name(buf, pos)?;
    let rtype = RecordType::from_u16(read_u16(buf, pos)?);
    let class = Class::from_u16(read_u16(buf, pos)?)?;
    let ttl_raw = read_u32(buf, pos)?;
    // RFC 2181 frames TTL as a signed 32-bit value; a wire value with the
    // sign bit set is non-conformant and clamped to zero rather than kept
    // negative.
    let ttl = if ttl_raw & 0x8000_0000 != 0 {
        0
    } else {
        ttl_raw
    };
    let rdlength = read_u16(buf, pos)? as usize;
    let rdata = RData::decode(buf, pos, rtype, rdlength)?;
    Ok(ResourceRecord {
        name,
        rtype,
        class,
        ttl,
        rdata,
    })
}

fn encode_rr(rr: &ResourceRecord, buf: &mut Vec<u8>) -> Result<()> {
    encode_name(&rr.name, buf)?;
    write_u16(buf, rr.rdata.record_type().to_u16());
    write_u16(buf, rr.class.to_u16());
    write_u32(buf, rr.ttl);

    let placeholder = buf.len();
    buf.extend_from_slice(&[0, 0]);
    let start = buf.len();
    rr.rdata.encode(buf)?;
    let len = buf.len() - start;
    let len_u16 = u16::try_from(len).map_err(|_| Error::MessageTooLong)?;
    buf[placeholder..placeholder + 2].copy_from_slice(&len_u16.to_be_bytes());
    Ok(())
}

/// Decodes a DNS name at `*pos`, following compression pointers
/// (RFC 1035 §4.1.4). A pointer must reference a strictly earlier offset
/// than its own, which both rejects loops and bounds the decode.
pub(crate) fn decode_name(buf: &[u8], pos: &mut usize) -> Result<Name> {
    let mut labels = Vec::new();
    let mut cur = *pos;
    let mut jumped = false;
    let mut real_end = 0usize;

    loop {
        if cur >= buf.len() {
            return Err(Error::Truncated { len: buf.len() });
        }
        let len_byte = buf[cur];
        if len_byte & 0xC0 == 0xC0 {
            if cur + 1 >= buf.len() {
                return Err(Error::Truncated { len: buf.len() });
            }
            let pointer = (((len_byte as usize) & 0x3F) << 8) | buf[cur + 1] as usize;
            if !jumped {
                real_end = cur + 2;
                jumped = true;
            }
            if pointer >= cur {
                return Err(Error::BadNamePointer { offset: cur });
            }
            cur = pointer;
            continue;
        }
        if len_byte & 0xC0 != 0 {
            return Err(Error::BadNamePointer { offset: cur });
        }
        if len_byte == 0 {
            cur += 1;
            break;
        }
        let len = len_byte as usize;
        if len > 63 {
            return Err(Error::LabelTooLong { offset: cur });
        }
        cur += 1;
        if cur + len > buf.len() {
            return Err(Error::Truncated { len: buf.len() });
        }
        labels.push(buf[cur..cur + len].to_vec());
        cur += len;
    }

    let name = Name(labels);
    name.check_total_length()?;
    *pos = if jumped { real_end } else { cur };
    Ok(name)
}

/// Encodes a DNS name without compression (RFC 1035 §4.1.4 compression is
/// a size optimization for messages this crate builds itself and is not
/// implemented here).
pub(crate) fn encode_name(name: &Name, buf: &mut Vec<u8>) -> Result<()> {
    name.check_total_length()?;
    for label in &name.0 {
        if label.len() > 63 {
            return Err(Error::LabelTooLong { offset: buf.len() });
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }
    buf.push(0);
    Ok(())
}

pub(crate) fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > buf.len() {
        return Err(Error::Truncated { len: buf.len() });
    }
    let value = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

pub(crate) fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(Error::Truncated { len: buf.len() });
    }
    let value = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(value)
}

pub(crate) fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RData;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn base_header() -> Header {
        Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            rcode: Rcode::NoError,
        }
    }

    fn round_trip(rdata: RData, rtype: RecordType) {
        let msg = Message {
            header: base_header(),
            questions: vec![Question {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: rtype,
                qclass: Class::In,
            }],
            answers: vec![ResourceRecord {
                name: Name::from_ascii("example.com.").unwrap(),
                rtype,
                class: Class::In,
                ttl: 300,
                rdata,
            }],
            authorities: vec![],
            additionals: vec![],
        };
        let bytes = msg.encode().unwrap();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn round_trips_a_record() {
        round_trip(RData::A(Ipv4Addr::new(93, 184, 216, 34)), RecordType::A);
    }

    #[test]
    fn round_trips_aaaa_record() {
        round_trip(
            RData::Aaaa(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x8443)),
            RecordType::Aaaa,
        );
    }

    #[test]
    fn round_trips_cname_record() {
        round_trip(
            RData::Cname(Name::from_ascii("target.example.com.").unwrap()),
            RecordType::Cname,
        );
    }

    #[test]
    fn round_trips_ptr_record() {
        round_trip(
            RData::Ptr(Name::from_ascii("host.example.com.").unwrap()),
            RecordType::Ptr,
        );
    }

    #[test]
    fn round_trips_ns_record() {
        round_trip(
            RData::Ns(Name::from_ascii("ns1.example.com.").unwrap()),
            RecordType::Ns,
        );
    }

    #[test]
    fn round_trips_txt_record() {
        round_trip(
            RData::Txt(vec![b"v=spf1 -all".to_vec(), b"second".to_vec()]),
            RecordType::Txt,
        );
    }

    #[test]
    fn round_trips_mx_record() {
        round_trip(
            RData::Mx {
                preference: 10,
                exchange: Name::from_ascii("mail.example.com.").unwrap(),
            },
            RecordType::Mx,
        );
    }

    #[test]
    fn round_trips_soa_record() {
        round_trip(
            RData::Soa {
                mname: Name::from_ascii("ns1.example.com.").unwrap(),
                rname: Name::from_ascii("hostmaster.example.com.").unwrap(),
                serial: 2026080200,
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            },
            RecordType::Soa,
        );
    }

    #[test]
    fn round_trips_unknown_record_type() {
        round_trip(
            RData::Unknown {
                rtype: 65280,
                data: vec![1, 2, 3, 4],
            },
            RecordType::Other(65280),
        );
    }

    #[test]
    fn empty_sections_decode_without_error() {
        let msg = Message {
            header: base_header(),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };
        let bytes = msg.encode().unwrap();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn truncated_message_is_rejected() {
        let bytes = [0u8; 5];
        let err = Message::decode(&bytes).unwrap_err();
        assert_eq!(err, Error::Truncated { len: 5 });
    }

    #[test]
    fn name_pointer_loop_is_rejected_promptly() {
        // Header claims 1 question; the question's name is a pointer to
        // itself at offset 12, which must be rejected, not followed.
        let mut bytes = vec![0u8; 12];
        bytes[5] = 1; // qdcount = 1
        bytes.push(0xC0);
        bytes.push(12);
        let err = Message::decode(&bytes).unwrap_err();
        assert_eq!(err, Error::BadNamePointer { offset: 12 });
    }

    #[test]
    fn label_length_over_63_is_rejected_on_encode() {
        // `Name::from_ascii` already rejects labels over 63 bytes; this
        // exercises `encode_name`'s own guard for a `Name` built by other
        // means (e.g. a future non-ASCII constructor).
        let name = Name(vec![vec![b'a'; 64]]);
        let mut buf = Vec::new();
        let err = encode_name(&name, &mut buf).unwrap_err();
        assert_eq!(err, Error::LabelTooLong { offset: 0 });
    }

    #[test]
    fn reserved_length_byte_bit_pattern_is_rejected_on_decode() {
        // A length byte with top bits `01` or `10` set is neither a valid
        // label length (top bits `00`) nor a compression pointer (top
        // bits `11`) — RFC 1035 §4.1.4 reserves this pattern.
        let mut pos = 0;
        let buf = [0b0100_0000u8];
        let err = decode_name(&buf, &mut pos).unwrap_err();
        assert_eq!(err, Error::BadNamePointer { offset: 0 });
    }

    #[test]
    fn rdlength_beyond_buffer_is_rejected() {
        let mut buf = Vec::new();
        encode_name(&Name::from_ascii("example.com.").unwrap(), &mut buf).unwrap();
        let mut pos = 0;
        // Claim a CNAME rdlength larger than any bytes actually present.
        let err = RData::decode(&buf, &mut pos, RecordType::Cname, 9999).unwrap_err();
        assert_eq!(err, Error::Truncated { len: buf.len() });
    }

    #[test]
    fn name_over_255_bytes_is_rejected_on_encode() {
        let label = vec![b'a'; 63];
        let labels = vec![label; 5];
        let name = Name(labels);
        let mut buf = Vec::new();
        let err = encode_name(&name, &mut buf).unwrap_err();
        assert_eq!(err, Error::NameTooLong);
    }

    #[test]
    fn name_is_case_insensitive() {
        let a = Name::from_ascii("EXAMPLE.com").unwrap();
        let b = Name::from_ascii("example.COM").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn from_ascii_rejects_empty_label() {
        assert_eq!(Name::from_ascii("a..b").unwrap_err(), Error::InvalidName);
        assert_eq!(Name::from_ascii(".a").unwrap_err(), Error::InvalidName);
    }

    #[test]
    fn deterministic_malformed_wire_corpus_never_panics() {
        // This deliberately small, fixed corpus covers every DNS-name length
        // prefix class and every message length up to a header plus one
        // question. It is a fuzz-style safety invariant, not a claim that
        // arbitrary trailing bytes must be rejected when section counts are
        // zero.
        for len in 0..=18 {
            for byte in [0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff] {
                let wire = vec![byte; len];
                let decoded = std::panic::catch_unwind(|| Message::decode(&wire));
                assert!(
                    decoded.is_ok(),
                    "decoder panicked for len={len}, byte={byte:#04x}"
                );
            }
        }
    }

    #[test]
    fn compression_pointer_consumes_only_its_two_wire_bytes() {
        // For every earlier pointer target in this bounded corpus, decoding a
        // compressed root name succeeds and leaves the caller positioned
        // immediately after the pointer rather than after its target.
        for pointer in 0..64usize {
            let cur = pointer + 1;
            let mut wire = vec![0; cur + 2];
            wire[cur] = 0xc0 | (((pointer >> 8) & 0x3f) as u8);
            wire[cur + 1] = pointer as u8;
            let mut pos = cur;

            assert_eq!(decode_name(&wire, &mut pos).unwrap(), Name::root());
            assert_eq!(pos, cur + 2, "pointer target {pointer}");
        }
    }
}
