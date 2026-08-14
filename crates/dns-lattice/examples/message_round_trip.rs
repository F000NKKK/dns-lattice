//! Builds a DNS response message, encodes it to wire bytes, and decodes it
//! back, showing that the two are equal.
//!
//! Run with: `cargo run -p dns-lattice --example message_round_trip`

use std::net::Ipv4Addr;

use dns_lattice::model::{
    Class, Header, Message, Name, Opcode, Question, RData, Rcode, RecordType, ResourceRecord,
};

fn main() {
    let message = Message {
        header: Header {
            id: 0x1234,
            qr: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: Name::from_ascii("example.com.").unwrap(),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: vec![ResourceRecord {
            name: Name::from_ascii("example.com.").unwrap(),
            rtype: RecordType::A,
            class: Class::In,
            ttl: 300,
            rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        }],
        authorities: vec![],
        additionals: vec![],
    };

    let bytes = message.encode().expect("message encodes");
    println!("encoded {} bytes", bytes.len());

    let decoded = Message::decode(&bytes).expect("message decodes");
    assert_eq!(message, decoded);
    println!("round-trip OK: {decoded:?}");
}
