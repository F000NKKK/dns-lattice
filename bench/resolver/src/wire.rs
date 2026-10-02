//! Hand-written DNS wire handling for the benchmark upstream.
//!
//! Neither library under test is used here: a query is parsed from raw
//! bytes and a response is built into raw bytes, so the upstream costs the
//! same for both contestants and the codec micro-benchmarks decode exactly
//! the same input on both sides.
//!
//! # Query names and answers
//!
//! The answer is chosen by the first label of the query name, never by
//! state, so a run is deterministic. The label's prefix up to the first `-`
//! selects a [`Mix`]: `a-<w>-<i>.bench.test.` returns one A record,
//! `aaaa-…` one AAAA record, `txt-…` one TXT record of about 1.1 KB (larger
//! than 512 bytes, within a 1232-byte EDNS payload), and `nx-…` NXDOMAIN
//! with an SOA in the authority section whose TTL and `minimum` equal the
//! configured TTL. Any other name is answered with REFUSED.
//!
//! # Response shape
//!
//! The id is echoed, QR/AA/RA are set, RD and the opcode are copied, and
//! the question is copied byte for byte (so mixed-case names survive).
//! Answer owner names are the compression pointer `0xC00C` to the question
//! name. An OPT record (payload [`EDNS_PAYLOAD`]) is added only when the
//! query carried one.
//!
//! Over [`Transport::Udp`] a response longer than [`udp_limit`] is replaced
//! by the header and question with TC set (RFC 1035 §4.2.1, RFC 6891
//! §6.2.5). Stream transports have no size limit.

use std::fmt;

/// Length of the fixed DNS header.
pub const HEADER_LEN: usize = 12;
/// RR type A.
pub const TYPE_A: u16 = 1;
/// RR type SOA.
pub const TYPE_SOA: u16 = 6;
/// RR type TXT.
pub const TYPE_TXT: u16 = 16;
/// RR type AAAA.
pub const TYPE_AAAA: u16 = 28;
/// RR type OPT (EDNS, RFC 6891).
pub const TYPE_OPT: u16 = 41;
/// Class IN.
pub const CLASS_IN: u16 = 1;
/// Response code NOERROR.
pub const RCODE_NOERROR: u8 = 0;
/// Response code NXDOMAIN.
pub const RCODE_NXDOMAIN: u8 = 3;
/// Response code REFUSED.
pub const RCODE_REFUSED: u8 = 5;
/// The classic UDP payload limit, and the floor for an advertised EDNS
/// payload size.
pub const MIN_UDP_PAYLOAD: u16 = 512;
/// The EDNS payload size both contestants advertise and the responder
/// echoes.
pub const EDNS_PAYLOAD: u16 = 1232;
/// The zone every benchmark name lives in.
pub const ZONE: &str = "bench.test";
/// The address of the first A record; further records count up from it.
pub const A_ADDR: [u8; 4] = [192, 0, 2, 1];
/// The address of the AAAA record (`2001:db8::1`).
pub const AAAA_ADDR: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// Number of character-strings in the TXT answer.
pub const TXT_STRINGS: usize = 5;
/// Length of each TXT character-string.
pub const TXT_STRING_LEN: usize = 220;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
/// Compression pointer to the question name at offset 12.
const QNAME_POINTER: [u8; 2] = [0xC0, 0x0C];
const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;

/// The query mix: which kind of answer a query name asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mix {
    /// One A record.
    A,
    /// One AAAA record.
    Aaaa,
    /// One TXT record of [`TXT_STRINGS`] × [`TXT_STRING_LEN`] bytes.
    Txt,
    /// NXDOMAIN with an SOA in the authority section.
    Nx,
}

impl Mix {
    /// Every mix, in a fixed order.
    pub const ALL: [Mix; 4] = [Mix::A, Mix::Aaaa, Mix::Txt, Mix::Nx];

    /// The first-label prefix and command-line name of this mix.
    pub fn as_str(self) -> &'static str {
        match self {
            Mix::A => "a",
            Mix::Aaaa => "aaaa",
            Mix::Txt => "txt",
            Mix::Nx => "nx",
        }
    }

    /// Parses a mix from its [`as_str`](Mix::as_str) name, ignoring ASCII
    /// case.
    pub fn parse(name: &str) -> Option<Mix> {
        Self::from_prefix(name.as_bytes())
    }

    /// The query type a client sends for this mix.
    pub fn qtype(self) -> u16 {
        match self {
            Mix::A | Mix::Nx => TYPE_A,
            Mix::Aaaa => TYPE_AAAA,
            Mix::Txt => TYPE_TXT,
        }
    }

    /// The fully qualified name `<mix>-<worker>-<index>.bench.test.`.
    pub fn fqdn(self, worker: u32, index: u32) -> String {
        format!("{}-{worker}-{index}.{ZONE}.", self.as_str())
    }

    /// Selects the mix from a query name's first label: the bytes before
    /// the first `-`, ignoring ASCII case.
    pub fn from_first_label(label: &[u8]) -> Option<Mix> {
        let prefix = label.split(|&byte| byte == b'-').next().unwrap_or(label);
        Self::from_prefix(prefix)
    }

    fn from_prefix(prefix: &[u8]) -> Option<Mix> {
        Mix::ALL
            .into_iter()
            .find(|mix| prefix.eq_ignore_ascii_case(mix.as_str().as_bytes()))
    }

    /// The answer the responder gives for this mix.
    pub fn answer(self) -> Answer {
        match self {
            Mix::A => Answer::A { count: 1 },
            Mix::Aaaa => Answer::Aaaa,
            Mix::Txt => Answer::Txt,
            Mix::Nx => Answer::NxDomain,
        }
    }
}

impl fmt::Display for Mix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The content of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `count` A records `192.0.2.1`, `192.0.2.2`, … (at most 254).
    A {
        /// Number of A records.
        count: u8,
    },
    /// One AAAA record [`AAAA_ADDR`].
    Aaaa,
    /// One TXT record of [`TXT_STRINGS`] × [`TXT_STRING_LEN`] bytes.
    Txt,
    /// NXDOMAIN with one SOA in the authority section.
    NxDomain,
    /// REFUSED with no records.
    Refused,
}

/// The transport a response is sent over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP: responses over [`udp_limit`] are truncated.
    Udp,
    /// TCP, TLS, HTTP or QUIC: no size limit.
    Stream,
}

/// How the responder answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseConfig {
    /// TTL of every record; also the SOA `minimum` of an NXDOMAIN answer.
    pub ttl: u32,
    /// The transport the response is sent over.
    pub transport: Transport,
}

/// Why a query could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The message ends before a field it announces.
    Truncated,
    /// The QR bit is set: the message is a response.
    NotAQuery,
    /// QDCOUNT is not 1.
    QuestionCount(u16),
    /// The query name uses a compression pointer.
    CompressedName,
    /// A label is longer than 63 bytes, or uses a reserved label type.
    LabelTooLong,
    /// A presentation-form name has an empty label.
    EmptyLabel,
    /// The encoded name is longer than 255 bytes.
    NameTooLong,
    /// The answer or authority section is not empty, or the additional
    /// section holds anything but a single OPT record.
    UnsupportedSection,
    /// Bytes follow the last announced record.
    TrailingBytes,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("message is truncated"),
            WireError::NotAQuery => f.write_str("message is a response, not a query"),
            WireError::QuestionCount(count) => write!(f, "QDCOUNT is {count}, expected 1"),
            WireError::CompressedName => f.write_str("query name is compressed"),
            WireError::LabelTooLong => f.write_str("label is longer than 63 bytes"),
            WireError::EmptyLabel => f.write_str("name has an empty label"),
            WireError::NameTooLong => f.write_str("name is longer than 255 bytes"),
            WireError::UnsupportedSection => {
                f.write_str("only a single OPT record may follow the question")
            }
            WireError::TrailingBytes => f.write_str("bytes follow the last record"),
        }
    }
}

impl std::error::Error for WireError {}

/// A parsed query, borrowing the bytes it was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    /// The message id.
    pub id: u16,
    /// The opcode (0-15).
    pub opcode: u8,
    /// Whether RD is set.
    pub recursion_desired: bool,
    /// The OPT record's advertised payload size, if the query carried one.
    pub edns_payload: Option<u16>,
    question: &'a [u8],
    qname_len: usize,
}

impl<'a> Query<'a> {
    /// The question exactly as received: QNAME, QTYPE and QCLASS.
    pub fn question(&self) -> &'a [u8] {
        self.question
    }

    /// The encoded query name, including its terminating zero byte.
    pub fn qname(&self) -> &'a [u8] {
        &self.question[..self.qname_len]
    }

    /// The first label of the query name (empty for the root name).
    pub fn first_label(&self) -> &'a [u8] {
        let len = usize::from(self.question[0]);
        &self.question[1..1 + len]
    }

    /// The query type.
    pub fn qtype(&self) -> u16 {
        u16::from_be_bytes([
            self.question[self.qname_len],
            self.question[self.qname_len + 1],
        ])
    }

    /// The query class.
    pub fn qclass(&self) -> u16 {
        u16::from_be_bytes([
            self.question[self.qname_len + 2],
            self.question[self.qname_len + 3],
        ])
    }
}

fn read_u16(bytes: &[u8], pos: usize) -> Result<u16, WireError> {
    match bytes.get(pos..pos + 2) {
        Some(field) => Ok(u16::from_be_bytes([field[0], field[1]])),
        None => Err(WireError::Truncated),
    }
}

/// Parses a query: one uncompressed question and at most one OPT record.
///
/// # Errors
///
/// Returns a [`WireError`] for anything else, including a response, a
/// compressed or over-long name, non-empty answer or authority sections,
/// and trailing bytes.
pub fn parse_query(bytes: &[u8]) -> Result<Query<'_>, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let id = read_u16(bytes, 0)?;
    let flags = read_u16(bytes, 2)?;
    if flags & FLAG_QR != 0 {
        return Err(WireError::NotAQuery);
    }
    let qdcount = read_u16(bytes, 4)?;
    let ancount = read_u16(bytes, 6)?;
    let nscount = read_u16(bytes, 8)?;
    let arcount = read_u16(bytes, 10)?;
    if qdcount != 1 {
        return Err(WireError::QuestionCount(qdcount));
    }
    if ancount != 0 || nscount != 0 || arcount > 1 {
        return Err(WireError::UnsupportedSection);
    }

    let start = HEADER_LEN;
    let mut pos = start;
    loop {
        let len = *bytes.get(pos).ok_or(WireError::Truncated)?;
        if len & 0xC0 == 0xC0 {
            return Err(WireError::CompressedName);
        }
        if usize::from(len) > MAX_LABEL_LEN {
            return Err(WireError::LabelTooLong);
        }
        pos += 1 + usize::from(len);
        if pos - start > MAX_NAME_LEN {
            return Err(WireError::NameTooLong);
        }
        if len == 0 {
            break;
        }
    }
    let qname_len = pos - start;
    if bytes.len() < pos + 4 {
        return Err(WireError::Truncated);
    }
    pos += 4;
    let question = &bytes[start..pos];

    let mut edns_payload = None;
    if arcount == 1 {
        // Root owner name, TYPE, CLASS (= payload size), TTL, RDLENGTH.
        let owner = *bytes.get(pos).ok_or(WireError::Truncated)?;
        if owner != 0 || read_u16(bytes, pos + 1)? != TYPE_OPT {
            return Err(WireError::UnsupportedSection);
        }
        edns_payload = Some(read_u16(bytes, pos + 3)?);
        let rdlen = usize::from(read_u16(bytes, pos + 9)?);
        pos += 11 + rdlen;
        if pos > bytes.len() {
            return Err(WireError::Truncated);
        }
    }
    if pos != bytes.len() {
        return Err(WireError::TrailingBytes);
    }

    Ok(Query {
        id,
        opcode: ((flags >> 11) & 0x0F) as u8,
        recursion_desired: flags & FLAG_RD != 0,
        edns_payload,
        question,
        qname_len,
    })
}

/// Appends `name` (presentation form, trailing dot optional) uncompressed.
///
/// # Errors
///
/// Returns [`WireError::EmptyLabel`], [`WireError::LabelTooLong`] or
/// [`WireError::NameTooLong`] for a name that cannot be encoded.
pub fn encode_name(name: &str, buf: &mut Vec<u8>) -> Result<(), WireError> {
    let start = buf.len();
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(WireError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(WireError::LabelTooLong);
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0);
    if buf.len() - start > MAX_NAME_LEN {
        return Err(WireError::NameTooLong);
    }
    Ok(())
}

/// Builds a query for `qname` (class IN, RD set), with an OPT record
/// advertising `edns_payload` when it is `Some`.
///
/// # Errors
///
/// Returns the [`encode_name`] error for an invalid name.
pub fn encode_query(
    id: u16,
    qname: &str,
    qtype: u16,
    edns_payload: Option<u16>,
) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::with_capacity(HEADER_LEN + qname.len() + 2 + 4 + 11);
    put_u16(&mut buf, id);
    put_u16(&mut buf, FLAG_RD);
    put_u16(&mut buf, 1);
    put_u16(&mut buf, 0);
    put_u16(&mut buf, 0);
    put_u16(&mut buf, u16::from(edns_payload.is_some()));
    encode_name(qname, &mut buf)?;
    put_u16(&mut buf, qtype);
    put_u16(&mut buf, CLASS_IN);
    if let Some(payload) = edns_payload {
        put_opt(&mut buf, payload);
    }
    Ok(buf)
}

/// The largest UDP response for a query advertising `edns_payload`: the
/// advertised size, but never below 512, or 512 without EDNS.
pub fn udp_limit(edns_payload: Option<u16>) -> usize {
    usize::from(edns_payload.map_or(MIN_UDP_PAYLOAD, |payload| payload.max(MIN_UDP_PAYLOAD)))
}

/// Answers `query` with the [`Mix`] its first label selects, or REFUSED.
pub fn respond(query: &Query<'_>, config: ResponseConfig) -> Vec<u8> {
    let answer = Mix::from_first_label(query.first_label()).map_or(Answer::Refused, Mix::answer);
    respond_with(query, answer, config)
}

/// Answers `query` with `answer`, truncating over UDP as described in the
/// [module documentation](self).
pub fn respond_with(query: &Query<'_>, answer: Answer, config: ResponseConfig) -> Vec<u8> {
    let full = build_response(query, answer, config.ttl, false);
    if config.transport == Transport::Udp && full.len() > udp_limit(query.edns_payload) {
        build_response(query, answer, config.ttl, true)
    } else {
        full
    }
}

fn build_response(query: &Query<'_>, answer: Answer, ttl: u32, truncated: bool) -> Vec<u8> {
    let rcode = match answer {
        Answer::NxDomain => RCODE_NXDOMAIN,
        Answer::Refused => RCODE_REFUSED,
        Answer::A { .. } | Answer::Aaaa | Answer::Txt => RCODE_NOERROR,
    };
    let (ancount, nscount) = match answer {
        _ if truncated => (0, 0),
        Answer::A { count } => (u16::from(count), 0),
        Answer::Aaaa | Answer::Txt => (1, 0),
        Answer::NxDomain => (0, 1),
        Answer::Refused => (0, 0),
    };
    let mut flags = FLAG_QR | FLAG_AA | FLAG_RA | (u16::from(query.opcode) << 11);
    flags |= u16::from(rcode);
    if query.recursion_desired {
        flags |= FLAG_RD;
    }
    if truncated {
        flags |= FLAG_TC;
    }

    let mut buf = Vec::with_capacity(512);
    put_u16(&mut buf, query.id);
    put_u16(&mut buf, flags);
    put_u16(&mut buf, 1);
    put_u16(&mut buf, ancount);
    put_u16(&mut buf, nscount);
    put_u16(&mut buf, u16::from(query.edns_payload.is_some()));
    buf.extend_from_slice(query.question());

    if !truncated {
        match answer {
            Answer::A { count } => {
                for offset in 0..count {
                    let mut addr = A_ADDR;
                    addr[3] = addr[3].wrapping_add(offset);
                    put_record(&mut buf, &QNAME_POINTER, TYPE_A, ttl, &addr);
                }
            }
            Answer::Aaaa => put_record(&mut buf, &QNAME_POINTER, TYPE_AAAA, ttl, &AAAA_ADDR),
            Answer::Txt => put_record(&mut buf, &QNAME_POINTER, TYPE_TXT, ttl, &txt_rdata()),
            Answer::NxDomain => {
                let mut owner = Vec::new();
                encode_name(ZONE, &mut owner).expect("the zone name is valid");
                put_record(&mut buf, &owner, TYPE_SOA, ttl, &soa_rdata(ttl));
            }
            Answer::Refused => {}
        }
    }
    if query.edns_payload.is_some() {
        put_opt(&mut buf, EDNS_PAYLOAD);
    }
    buf
}

/// The TXT answer's RDATA: [`TXT_STRINGS`] deterministic lowercase
/// character-strings of [`TXT_STRING_LEN`] bytes each.
pub fn txt_rdata() -> Vec<u8> {
    let mut rdata = Vec::with_capacity(TXT_STRINGS * (1 + TXT_STRING_LEN));
    for string in 0..TXT_STRINGS {
        rdata.push(TXT_STRING_LEN as u8);
        for byte in 0..TXT_STRING_LEN {
            rdata.push(b'a' + ((string * 7 + byte) % 26) as u8);
        }
    }
    rdata
}

fn soa_rdata(minimum: u32) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(64);
    encode_name("ns.bench.test", &mut rdata).expect("the SOA mname is valid");
    encode_name("hostmaster.bench.test", &mut rdata).expect("the SOA rname is valid");
    for value in [1, 3600, 600, 86_400, minimum] {
        rdata.extend_from_slice(&u32::to_be_bytes(value));
    }
    rdata
}

fn put_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_record(buf: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
    buf.extend_from_slice(owner);
    put_u16(buf, rtype);
    put_u16(buf, CLASS_IN);
    buf.extend_from_slice(&ttl.to_be_bytes());
    put_u16(
        buf,
        u16::try_from(rdata.len()).expect("benchmark RDATA fits in 64 KiB"),
    );
    buf.extend_from_slice(rdata);
}

fn put_opt(buf: &mut Vec<u8>, payload: u16) {
    // Root owner, TYPE OPT, CLASS = payload, extended RCODE/version/flags
    // 0, no options.
    buf.push(0);
    put_u16(buf, TYPE_OPT);
    put_u16(buf, payload);
    buf.extend_from_slice(&[0, 0, 0, 0]);
    put_u16(buf, 0);
}

/// One named response message used as identical codec input for both
/// libraries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    /// Short identifier used as the benchmark parameter.
    pub name: &'static str,
    /// The response bytes.
    pub bytes: Vec<u8>,
}

/// The codec fixtures: responses with an OPT record, built over a stream
/// transport (never truncated) with TTL 300.
///
/// - `a`: one A record;
/// - `aaaa`: one AAAA record;
/// - `a10`: ten A records;
/// - `txt`: one TXT record of about 1.1 KB;
/// - `nxdomain`: NXDOMAIN with an SOA in the authority section.
pub fn codec_fixtures() -> Vec<Fixture> {
    let cases: [(&'static str, Mix, Answer); 5] = [
        ("a", Mix::A, Answer::A { count: 1 }),
        ("aaaa", Mix::Aaaa, Answer::Aaaa),
        ("a10", Mix::A, Answer::A { count: 10 }),
        ("txt", Mix::Txt, Answer::Txt),
        ("nxdomain", Mix::Nx, Answer::NxDomain),
    ];
    let config = ResponseConfig {
        ttl: 300,
        transport: Transport::Stream,
    };
    cases
        .into_iter()
        .map(|(name, mix, answer)| {
            let query = encode_query(0x1234, &mix.fqdn(0, 0), mix.qtype(), Some(EDNS_PAYLOAD))
                .expect("fixture names are valid");
            let parsed = parse_query(&query).expect("fixture queries parse");
            Fixture {
                name,
                bytes: respond_with(&parsed, answer, config),
            }
        })
        .collect()
}
