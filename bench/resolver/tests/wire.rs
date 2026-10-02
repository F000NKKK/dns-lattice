//! The hand-written responder wire format: query parsing (success and
//! rejection), response shape, the UDP truncation rule, and that both
//! libraries under test decode the codec fixtures to the same content.

use dns_lattice::model::{Message, RData, Rcode, RecordType};
use dns_lattice_bench_resolver::wire::{
    self, Answer, EDNS_PAYLOAD, Mix, ResponseConfig, Transport, WireError,
};
use hickory_proto::op::{Message as HkMessage, ResponseCode};

const STREAM: ResponseConfig = ResponseConfig {
    ttl: 300,
    transport: Transport::Stream,
};
const UDP: ResponseConfig = ResponseConfig {
    ttl: 300,
    transport: Transport::Udp,
};

fn query(qname: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    wire::encode_query(0xBEEF, qname, qtype, edns).expect("valid query name")
}

fn flags(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn count(bytes: &[u8], index: usize) -> u16 {
    u16::from_be_bytes([bytes[4 + 2 * index], bytes[5 + 2 * index]])
}

#[test]
fn encoded_query_parses_back() {
    let bytes = query("A-3-7.Bench.Test.", wire::TYPE_AAAA, Some(EDNS_PAYLOAD));
    let parsed = wire::parse_query(&bytes).unwrap();
    assert_eq!(parsed.id, 0xBEEF);
    assert!(parsed.recursion_desired);
    assert_eq!(parsed.opcode, 0);
    assert_eq!(parsed.edns_payload, Some(EDNS_PAYLOAD));
    assert_eq!(parsed.first_label(), b"A-3-7");
    assert_eq!(parsed.qtype(), wire::TYPE_AAAA);
    assert_eq!(parsed.qclass(), wire::CLASS_IN);
    assert_eq!(parsed.qname(), b"\x05A-3-7\x05Bench\x04Test\x00");

    let plain = query("a-0-0.bench.test", wire::TYPE_A, None);
    assert_eq!(wire::parse_query(&plain).unwrap().edns_payload, None);
}

#[test]
fn queries_built_by_dns_lattice_parse() {
    let bytes = query("txt-1-2.bench.test.", wire::TYPE_TXT, Some(EDNS_PAYLOAD));
    let message = Message::decode(&bytes).unwrap();
    let reencoded = message.encode().unwrap();
    assert_eq!(reencoded, bytes);
    assert!(wire::parse_query(&reencoded).is_ok());
}

#[test]
fn malformed_queries_are_rejected() {
    let good = query("a-0-0.bench.test.", wire::TYPE_A, None);

    assert_eq!(wire::parse_query(&good[..11]), Err(WireError::Truncated));
    assert_eq!(
        wire::parse_query(&good[..good.len() - 1]),
        Err(WireError::Truncated)
    );

    let mut response = good.clone();
    response[2] |= 0x80;
    assert_eq!(wire::parse_query(&response), Err(WireError::NotAQuery));

    let mut two_questions = good.clone();
    two_questions[5] = 2;
    assert_eq!(
        wire::parse_query(&two_questions),
        Err(WireError::QuestionCount(2))
    );

    let mut with_answer = good.clone();
    with_answer[7] = 1;
    assert_eq!(
        wire::parse_query(&with_answer),
        Err(WireError::UnsupportedSection)
    );

    let mut compressed = good.clone();
    compressed.truncate(12);
    compressed.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    assert_eq!(
        wire::parse_query(&compressed),
        Err(WireError::CompressedName)
    );

    let mut long_label = good.clone();
    long_label[12] = 64;
    assert_eq!(wire::parse_query(&long_label), Err(WireError::LabelTooLong));

    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(wire::parse_query(&trailing), Err(WireError::TrailingBytes));

    // An additional record that is not OPT.
    let mut not_opt = good.clone();
    not_opt[11] = 1;
    not_opt.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        wire::parse_query(&not_opt),
        Err(WireError::UnsupportedSection)
    );

    // An OPT record whose RDLENGTH runs past the end.
    let mut short_opt = query("a-0-0.bench.test.", wire::TYPE_A, Some(EDNS_PAYLOAD));
    let last = short_opt.len() - 1;
    short_opt[last] = 4;
    assert_eq!(wire::parse_query(&short_opt), Err(WireError::Truncated));
}

#[test]
fn over_long_names_are_rejected() {
    let label = "x".repeat(63);
    let long = [label.as_str(); 4].join(".");
    assert_eq!(
        wire::encode_query(1, &long, wire::TYPE_A, None),
        Err(WireError::NameTooLong)
    );
    assert_eq!(
        wire::encode_query(1, &"y".repeat(64), wire::TYPE_A, None),
        Err(WireError::LabelTooLong)
    );
    assert_eq!(
        wire::encode_query(1, "a..test", wire::TYPE_A, None),
        Err(WireError::EmptyLabel)
    );

    // 4 labels of 63 bytes encode to 257 bytes on the wire.
    let mut bytes = query("a-0-0.bench.test.", wire::TYPE_A, None);
    bytes.truncate(12);
    for _ in 0..4 {
        bytes.push(63);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(wire::parse_query(&bytes), Err(WireError::NameTooLong));
}

#[test]
fn mix_is_selected_by_first_label_prefix() {
    assert_eq!(Mix::from_first_label(b"a-1-2"), Some(Mix::A));
    assert_eq!(Mix::from_first_label(b"AAAA-1-2"), Some(Mix::Aaaa));
    assert_eq!(Mix::from_first_label(b"txt-0-0"), Some(Mix::Txt));
    assert_eq!(Mix::from_first_label(b"nx"), Some(Mix::Nx));
    assert_eq!(Mix::from_first_label(b"aa-1-2"), None);
    assert_eq!(Mix::from_first_label(b""), None);
    assert_eq!(Mix::parse("TXT"), Some(Mix::Txt));
    assert_eq!(Mix::Aaaa.fqdn(3, 9), "aaaa-3-9.bench.test.");
    for mix in Mix::ALL {
        assert_eq!(Mix::parse(&mix.to_string()), Some(mix));
    }
}

#[test]
fn response_echoes_id_flags_and_question_bytes() {
    let bytes = query("A-1-2.BeNcH.test.", wire::TYPE_A, None);
    let parsed = wire::parse_query(&bytes).unwrap();
    let response = wire::respond(&parsed, STREAM);

    assert_eq!(&response[..2], &0xBEEFu16.to_be_bytes());
    let bits = flags(&response);
    assert_eq!(bits & 0x8000, 0x8000, "QR");
    assert_eq!(bits & 0x0400, 0x0400, "AA");
    assert_eq!(bits & 0x0100, 0x0100, "RD copied");
    assert_eq!(bits & 0x0080, 0x0080, "RA");
    assert_eq!(bits & 0x000F, 0, "NOERROR");
    assert_eq!(
        &response[12..12 + parsed.question().len()],
        parsed.question()
    );
    // No OPT in the query, none in the response.
    assert_eq!(count(&response, 3), 0);

    let mut no_rd = bytes.clone();
    no_rd[2] &= !0x01;
    let parsed = wire::parse_query(&no_rd).unwrap();
    assert_eq!(flags(&wire::respond(&parsed, STREAM)) & 0x0100, 0);
}

#[test]
fn unknown_names_are_refused() {
    let bytes = query("other.bench.test.", wire::TYPE_A, Some(EDNS_PAYLOAD));
    let parsed = wire::parse_query(&bytes).unwrap();
    let response = wire::respond(&parsed, UDP);
    assert_eq!(flags(&response) & 0x000F, u16::from(wire::RCODE_REFUSED));
    assert_eq!(count(&response, 1), 0);
    assert_eq!(count(&response, 3), 1, "OPT echoed");
}

#[test]
fn every_mix_decodes_identically_in_both_libraries() {
    for mix in Mix::ALL {
        let bytes = query(&mix.fqdn(7, 11), mix.qtype(), Some(EDNS_PAYLOAD));
        let parsed = wire::parse_query(&bytes).unwrap();
        let response = wire::respond(&parsed, STREAM);

        let dl = Message::decode(&response).unwrap();
        let hk = HkMessage::from_vec(&response).unwrap();
        assert_eq!(dl.header.id, hk.metadata.id);
        assert!(dl.header.qr && dl.header.authoritative && dl.header.recursion_available);
        assert!(!dl.header.truncated && !hk.metadata.truncation);
        assert_eq!(dl.answers.len(), hk.answers.len(), "{mix}");
        assert_eq!(dl.authorities.len(), hk.authorities.len(), "{mix}");
        assert_eq!(
            hk.edns.as_ref().map(|edns| edns.max_payload()),
            Some(EDNS_PAYLOAD)
        );

        match mix {
            Mix::A => {
                assert_eq!(dl.answers[0].rdata, RData::A([192, 0, 2, 1].into()));
                assert_eq!(dl.answers[0].ttl, 300);
            }
            Mix::Aaaa => {
                assert_eq!(dl.answers[0].rdata, RData::Aaaa(wire::AAAA_ADDR.into()));
            }
            Mix::Txt => match &dl.answers[0].rdata {
                RData::Txt(strings) => {
                    assert_eq!(strings.len(), wire::TXT_STRINGS);
                    assert!(strings.iter().all(|s| s.len() == wire::TXT_STRING_LEN));
                }
                other => panic!("unexpected TXT rdata {other:?}"),
            },
            Mix::Nx => {
                assert_eq!(dl.header.rcode, Rcode::NxDomain);
                assert_eq!(hk.metadata.response_code, ResponseCode::NXDomain);
                assert!(dl.answers.is_empty());
                assert_eq!(dl.authorities[0].rtype, RecordType::Soa);
                assert_eq!(dl.authorities[0].ttl, 300);
                match dl.authorities[0].rdata {
                    RData::Soa { minimum, .. } => assert_eq!(minimum, 300),
                    ref other => panic!("unexpected SOA rdata {other:?}"),
                }
            }
        }
    }
}

#[test]
fn udp_truncates_over_the_limit_and_keeps_opt() {
    let name = Mix::Txt.fqdn(255, 1023);

    // Without EDNS the TXT answer exceeds 512 bytes: header + question, TC.
    let plain = query(&name, wire::TYPE_TXT, None);
    let parsed = wire::parse_query(&plain).unwrap();
    let truncated = wire::respond(&parsed, UDP);
    assert_eq!(flags(&truncated) & 0x0200, 0x0200, "TC");
    assert_eq!(count(&truncated, 1), 0);
    assert_eq!(count(&truncated, 3), 0);
    assert_eq!(truncated.len(), 12 + parsed.question().len());
    assert!(wire::respond(&parsed, STREAM).len() > 512);

    // With a 1232-byte EDNS payload the full answer fits.
    let edns = query(&name, wire::TYPE_TXT, Some(EDNS_PAYLOAD));
    let parsed = wire::parse_query(&edns).unwrap();
    let full = wire::respond(&parsed, UDP);
    assert_eq!(flags(&full) & 0x0200, 0);
    assert!(full.len() > 512 && full.len() <= usize::from(EDNS_PAYLOAD));
    assert_eq!(count(&full, 1), 1);
    assert_eq!(count(&full, 3), 1, "OPT echoed");

    // An advertised payload below 512 is treated as 512.
    let tiny = query(&name, wire::TYPE_TXT, Some(100));
    let parsed = wire::parse_query(&tiny).unwrap();
    assert_eq!(wire::udp_limit(Some(100)), 512);
    let truncated = wire::respond(&parsed, UDP);
    assert_eq!(flags(&truncated) & 0x0200, 0x0200);
    assert_eq!(count(&truncated, 3), 1, "OPT kept in a truncated reply");
    assert!(Message::decode(&truncated).unwrap().header.truncated);

    // Small answers are never truncated.
    let a = query(&Mix::A.fqdn(0, 0), wire::TYPE_A, None);
    let parsed = wire::parse_query(&a).unwrap();
    assert_eq!(flags(&wire::respond(&parsed, UDP)) & 0x0200, 0);
}

#[test]
fn codec_fixtures_decode_in_both_libraries() {
    let fixtures = wire::codec_fixtures();
    let names: Vec<_> = fixtures.iter().map(|fixture| fixture.name).collect();
    assert_eq!(names, ["a", "aaaa", "a10", "txt", "nxdomain"]);
    for fixture in &fixtures {
        let dl = Message::decode(&fixture.bytes).unwrap();
        let hk = HkMessage::from_vec(&fixture.bytes).unwrap();
        assert_eq!(dl.answers.len(), hk.answers.len(), "{}", fixture.name);
        // dns-lattice keeps OPT as an ordinary additional record; hickory
        // lifts it into `edns`.
        assert_eq!(dl.additionals.len(), 1);
        assert!(hk.edns.is_some());
        // Both libraries re-encode to a message that decodes back.
        assert_eq!(Message::decode(&dl.encode().unwrap()).unwrap(), dl);
        assert!(HkMessage::from_vec(&hk.to_vec().unwrap()).is_ok());
    }
    let a10 = &fixtures[2];
    assert_eq!(Message::decode(&a10.bytes).unwrap().answers.len(), 10);
    let ten = wire::respond_with(
        &wire::parse_query(&query("a-0-0.bench.test.", wire::TYPE_A, None)).unwrap(),
        Answer::A { count: 10 },
        STREAM,
    );
    assert_eq!(count(&ten, 1), 10);
}
