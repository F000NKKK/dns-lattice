//! EDNS(0) (RFC 6891): the OPT pseudo-record's fields as a typed value.
//!
//! An OPT record travels in a message's additional section as an ordinary
//! [`ResourceRecord`] whose `rdata` is
//! [`RData::Unknown`] with `rtype` 41. [`Message::edns`] parses that record
//! into an [`Edns`] value and [`Message::set_edns`] replaces it; the
//! underlying record keeps round-tripping unchanged when neither is called.
//!
//! On the wire an OPT record has:
//!
//! - owner name: the root;
//! - `TYPE`: 41;
//! - `CLASS`: the sender's UDP payload size;
//! - `TTL`: extended `RCODE` (8 bits), version (8 bits), the DO flag (1 bit)
//!   and 15 reserved Z bits;
//! - `RDATA`: a sequence of options, each `code (2) | length (2) | data`.
//!
//! Z bits other than DO are ignored when read and written as zero.
//!
//! [`Message::edns`]: crate::message::Message::edns
//! [`Message::set_edns`]: crate::message::Message::set_edns

use dns_lattice_core::{Error, Result};

use crate::message::{Name, ResourceRecord};
use crate::record::{Class, RData, RecordType};

/// The `TYPE` value of the OPT pseudo-record (RFC 6891 §6.1.1).
pub(crate) const OPT_RTYPE: u16 = 41;

const DNSSEC_OK_BIT: u32 = 0x0000_8000;

/// The EDNS(0) parameters a message carries in its OPT pseudo-record
/// (RFC 6891 §6.1).
///
/// Build one with [`Edns::new`] and the `set_*` methods, attach it with
/// [`Message::set_edns`](crate::message::Message::set_edns), and read it
/// back with [`Message::edns`](crate::message::Message::edns).
///
/// ```
/// use dns_lattice_model::{Edns, EdnsOption};
///
/// let mut edns = Edns::new(1232);
/// edns.set_dnssec_ok(true)
///     .push_option(EdnsOption::new(12, vec![0; 4]).unwrap());
/// assert_eq!(edns.udp_payload_size(), 1232);
/// assert_eq!(edns.version(), 0);
/// assert!(edns.dnssec_ok());
/// assert_eq!(edns.options().len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    options: Vec<EdnsOption>,
}

impl Edns {
    /// Creates EDNS parameters advertising `udp_payload_size`, with version
    /// 0, extended `RCODE` 0, the DO flag clear and no options.
    pub fn new(udp_payload_size: u16) -> Self {
        Edns {
            udp_payload_size,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// The UDP payload size the sender can reassemble: the raw wire value
    /// of the OPT record's `CLASS`. It is not clamped, so values below 512
    /// (including 0) are returned as received.
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// Sets the advertised UDP payload size. The value is stored as given.
    pub fn set_udp_payload_size(&mut self, size: u16) -> &mut Self {
        self.udp_payload_size = size;
        self
    }

    /// The upper 8 bits of the 12-bit extended `RCODE`; the lower 4 bits
    /// live in the message header's `rcode`.
    pub fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    /// Sets the upper 8 bits of the 12-bit extended `RCODE`.
    pub fn set_extended_rcode(&mut self, value: u8) -> &mut Self {
        self.extended_rcode = value;
        self
    }

    /// The EDNS version. Only version 0 is defined.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Sets the EDNS version. Any value is stored; deciding whether a
    /// version is supported is left to the caller.
    pub fn set_version(&mut self, version: u8) -> &mut Self {
        self.version = version;
        self
    }

    /// Whether the DNSSEC OK (DO) flag is set (RFC 3225).
    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// Sets or clears the DNSSEC OK (DO) flag.
    pub fn set_dnssec_ok(&mut self, dnssec_ok: bool) -> &mut Self {
        self.dnssec_ok = dnssec_ok;
        self
    }

    /// The options, in wire order.
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }

    /// Appends an option after the existing ones.
    pub fn push_option(&mut self, option: EdnsOption) -> &mut Self {
        self.options.push(option);
        self
    }

    /// Removes every option.
    pub fn clear_options(&mut self) -> &mut Self {
        self.options.clear();
        self
    }

    /// Parses an OPT record. The caller has already checked that `rdata`
    /// is an OPT `RData::Unknown`.
    pub(crate) fn from_record(record: &ResourceRecord, data: &[u8]) -> Result<Self> {
        if !record.name.is_root() {
            return Err(Error::InvalidName);
        }
        let declared = u16::try_from(data.len()).unwrap_or(u16::MAX);
        let mut options = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if data.len() - pos < 4 {
                return Err(Error::RDataLengthMismatch { declared });
            }
            let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if data.len() - pos < len {
                return Err(Error::RDataLengthMismatch { declared });
            }
            options.push(EdnsOption {
                code,
                data: data[pos..pos + len].to_vec(),
            });
            pos += len;
        }

        let ttl = record.ttl;
        Ok(Edns {
            udp_payload_size: record.class.to_u16(),
            extended_rcode: (ttl >> 24) as u8,
            version: (ttl >> 16) as u8,
            dnssec_ok: ttl & DNSSEC_OK_BIT != 0,
            options,
        })
    }

    /// Builds the OPT record for these parameters.
    pub(crate) fn to_record(&self) -> ResourceRecord {
        let mut data = Vec::new();
        for option in &self.options {
            data.extend_from_slice(&option.code.to_be_bytes());
            // `EdnsOption::new` guarantees the length fits in 16 bits.
            data.extend_from_slice(&(option.data.len() as u16).to_be_bytes());
            data.extend_from_slice(&option.data);
        }
        let mut ttl = (u32::from(self.extended_rcode) << 24) | (u32::from(self.version) << 16);
        if self.dnssec_ok {
            ttl |= DNSSEC_OK_BIT;
        }
        ResourceRecord {
            name: Name::root(),
            rtype: RecordType::Other(OPT_RTYPE),
            class: opt_class(self.udp_payload_size),
            ttl,
            rdata: RData::Unknown {
                rtype: OPT_RTYPE,
                data,
            },
        }
    }
}

/// Maps an OPT `CLASS` (a payload size) to the [`Class`] the decoder
/// produces for it, so a built record equals its decoded form.
pub(crate) fn opt_class(value: u16) -> Class {
    // `Class::from_u16` rejects only 0, which an OPT carries as `Other(0)`.
    Class::from_u16(value).unwrap_or(Class::Other(value))
}

/// Whether `rdata` is an OPT pseudo-record's data, returning its bytes.
pub(crate) fn opt_data(rdata: &RData) -> Option<&[u8]> {
    match rdata {
        RData::Unknown { rtype, data } if *rtype == OPT_RTYPE => Some(data),
        _ => None,
    }
}

/// One EDNS option (RFC 6891 §6.1.2): an option code and its raw data.
///
/// The data is kept as bytes; this type does not interpret any option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    code: u16,
    data: Vec<u8>,
}

impl EdnsOption {
    /// Creates an option with `code` and `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MessageTooLong`] if `data` is longer than 65535
    /// bytes, the most an option's 16-bit length field can describe.
    pub fn new(code: u16, data: Vec<u8>) -> Result<Self> {
        if data.len() > u16::MAX as usize {
            return Err(Error::MessageTooLong);
        }
        Ok(EdnsOption { code, data })
    }

    /// The option code.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// The option's raw data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Header, Message, Opcode, Question, Rcode};
    use std::net::Ipv4Addr;

    fn query() -> Message {
        Message {
            header: Header {
                id: 0x1234,
                qr: false,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn a_record(name: &str, last_octet: u8) -> ResourceRecord {
        ResourceRecord {
            name: Name::from_ascii(name).unwrap(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, last_octet)),
        }
    }

    fn opt_record(name: Name, class: Class, ttl: u32, data: Vec<u8>) -> ResourceRecord {
        ResourceRecord {
            name,
            rtype: RecordType::Other(OPT_RTYPE),
            class,
            ttl,
            rdata: RData::Unknown {
                rtype: OPT_RTYPE,
                data,
            },
        }
    }

    /// Encodes and decodes `message`, returning the wire bytes and the
    /// decoded message.
    fn wire_round_trip(message: &Message) -> (Vec<u8>, Message) {
        let bytes = message.encode().unwrap();
        let decoded = Message::decode(&bytes).unwrap();
        (bytes, decoded)
    }

    #[test]
    fn round_trip_has_exact_opt_wire_bytes() {
        let mut edns = Edns::new(1232);
        edns.set_extended_rcode(1)
            .set_version(0)
            .set_dnssec_ok(true)
            .push_option(EdnsOption::new(10, vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap())
            .push_option(EdnsOption::new(12, Vec::new()).unwrap());
        let mut message = query();
        message.set_edns(Some(edns.clone()));

        let (bytes, decoded) = wire_round_trip(&message);
        let expected_opt: &[u8] = &[
            0x00, // root owner
            0x00, 0x29, // TYPE 41
            0x04, 0xD0, // CLASS = payload 1232
            0x01, 0x00, 0x80, 0x00, // TTL: ext-rcode 1, version 0, DO
            0x00, 0x10, // RDLENGTH 16
            0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, // option 10
            0x00, 0x0C, 0x00, 0x00, // option 12, empty
        ];
        assert!(bytes.ends_with(expected_opt), "wire: {bytes:02x?}");
        assert_eq!(&bytes[10..12], &[0x00, 0x01], "ARCOUNT");
        assert_eq!(decoded, message);
        assert_eq!(decoded.edns(), Ok(Some(edns)));
    }

    #[test]
    fn small_payload_sizes_round_trip() {
        for size in [0u16, 1, 3] {
            let mut message = query();
            message.set_edns(Some(Edns::new(size)));
            let (bytes, decoded) = wire_round_trip(&message);
            assert_eq!(decoded, message, "payload {size}");
            assert_eq!(decoded.edns(), Ok(Some(Edns::new(size))), "payload {size}");
            assert_eq!(decoded.encode().unwrap(), bytes, "payload {size}");
        }
    }

    #[test]
    fn high_extended_rcode_survives_decode() {
        let mut edns = Edns::new(4096);
        edns.set_extended_rcode(0x80).set_version(0xFF);
        let mut message = query();
        message.set_edns(Some(edns.clone()));
        let (_, decoded) = wire_round_trip(&message);
        assert_eq!(decoded.additionals[0].ttl, 0x80FF_0000);
        assert_eq!(decoded.edns(), Ok(Some(edns)));
    }

    #[test]
    fn untouched_opt_with_z_bits_round_trips_byte_exact() {
        let mut message = query();
        message.additionals.push(opt_record(
            Name::root(),
            Class::Other(512),
            0x0000_8001,
            vec![0x00, 0x0C, 0x00, 0x01, 0xAA],
        ));
        let (bytes, decoded) = wire_round_trip(&message);
        assert_eq!(decoded, message);
        assert_eq!(decoded.encode().unwrap(), bytes);

        let edns = decoded.edns().unwrap().unwrap();
        assert!(edns.dnssec_ok());
        assert_eq!(edns.udp_payload_size(), 512);
        assert_eq!(edns.options(), &[EdnsOption::new(12, vec![0xAA]).unwrap()]);

        // Re-encoding through `set_edns` drops the unknown Z bit.
        let mut rebuilt = decoded.clone();
        rebuilt.set_edns(Some(edns));
        assert_eq!(rebuilt.additionals[0].ttl, 0x0000_8000);
    }

    #[test]
    fn non_opt_records_keep_class_zero_and_ttl_rules() {
        let mut class_zero = query();
        let mut record = a_record("example.com.", 1);
        record.class = Class::Other(0);
        class_zero.answers.push(record);
        let bytes = class_zero.encode().unwrap();
        assert_eq!(Message::decode(&bytes), Err(Error::InvalidClass(0)));

        let mut negative_ttl = query();
        let mut record = a_record("example.com.", 1);
        record.ttl = 0x8000_0001;
        negative_ttl.answers.push(record);
        let decoded = Message::decode(&negative_ttl.encode().unwrap()).unwrap();
        assert_eq!(decoded.answers[0].ttl, 0);
    }

    #[test]
    fn set_edns_replaces_and_removes_keeping_other_additionals_in_order() {
        let mut message = query();
        message.additionals = vec![
            a_record("a.example.", 1),
            Edns::new(512).to_record(),
            a_record("b.example.", 2),
            Edns::new(4096).to_record(),
            a_record("c.example.", 3),
        ];

        let mut edns = Edns::new(1232);
        edns.set_dnssec_ok(true);
        message.set_edns(Some(edns.clone()));
        assert_eq!(
            message.additionals,
            vec![
                a_record("a.example.", 1),
                a_record("b.example.", 2),
                a_record("c.example.", 3),
                edns.to_record(),
            ]
        );
        assert_eq!(message.edns(), Ok(Some(edns)));

        message.set_edns(None);
        assert_eq!(
            message.additionals,
            vec![
                a_record("a.example.", 1),
                a_record("b.example.", 2),
                a_record("c.example.", 3),
            ]
        );
        assert_eq!(message.edns(), Ok(None));
    }

    #[test]
    fn opt_outside_the_additional_section_is_not_inspected() {
        let mut message = query();
        message.answers.push(Edns::new(512).to_record());
        message.authorities.push(Edns::new(512).to_record());
        assert_eq!(message.edns(), Ok(None));
        message.set_edns(None);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.authorities.len(), 1);
    }

    #[test]
    fn two_opt_records_are_a_count_mismatch() {
        let mut message = query();
        message.additionals.push(Edns::new(512).to_record());
        message.additionals.push(Edns::new(1232).to_record());
        assert_eq!(message.edns(), Err(Error::CountMismatch));
    }

    #[test]
    fn non_root_owner_is_an_invalid_name() {
        let mut message = query();
        message.additionals.push(opt_record(
            Name::from_ascii("example.com.").unwrap(),
            Class::Other(512),
            0,
            Vec::new(),
        ));
        assert_eq!(message.edns(), Err(Error::InvalidName));
    }

    #[test]
    fn malformed_option_layout_is_an_rdata_length_mismatch() {
        let cases: [Vec<u8>; 5] = [
            // 1, 2 and 3 trailing bytes after a complete option.
            vec![0x00, 0x0C, 0x00, 0x00, 0x00],
            vec![0x00, 0x0C, 0x00, 0x00, 0x00, 0x0A],
            vec![0x00, 0x0C, 0x00, 0x00, 0x00, 0x0A, 0x00],
            // Option data longer than the remaining RDATA.
            vec![0x00, 0x0A, 0x00, 0x08, 1, 2],
            vec![0x00, 0x0A, 0x00, 0x01],
        ];
        for data in cases {
            let declared = data.len() as u16;
            let mut message = query();
            message
                .additionals
                .push(opt_record(Name::root(), Class::Other(512), 0, data.clone()));
            // The record itself still decodes; only `edns()` rejects it.
            let (_, decoded) = wire_round_trip(&message);
            assert_eq!(
                decoded.edns(),
                Err(Error::RDataLengthMismatch { declared }),
                "rdata {data:02x?}"
            );
        }
    }

    #[test]
    fn oversized_option_data_is_message_too_long() {
        assert_eq!(
            EdnsOption::new(1, vec![0; 65_536]),
            Err(Error::MessageTooLong)
        );
        let max = EdnsOption::new(1, vec![0; 65_535]).unwrap();
        assert_eq!(max.code(), 1);
        assert_eq!(max.data().len(), 65_535);
    }

    #[test]
    fn edns_accessors_and_clear_options() {
        let mut edns = Edns::new(512);
        assert_eq!(edns.extended_rcode(), 0);
        assert!(!edns.dnssec_ok());
        assert!(edns.options().is_empty());
        edns.set_udp_payload_size(1400)
            .push_option(EdnsOption::new(8, vec![1]).unwrap())
            .clear_options();
        assert_eq!(edns.udp_payload_size(), 1400);
        assert!(edns.options().is_empty());
    }
}
