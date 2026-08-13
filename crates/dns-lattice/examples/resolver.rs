//! Builds a `Resolver` from a static split-DNS policy with an in-process
//! fake upstream backend per group, then resolves the same name twice to
//! show the second call is served from the in-memory answer cache.
//!
//! `Resolver::resolve` is `async fn`, so
//! this example runs inside a `tokio` runtime even though the fake
//! backends below do no real socket I/O.
//!
//! Run with: `cargo run -p dns-lattice --example resolver`

use std::net::Ipv4Addr;

use async_trait::async_trait;
use dns_lattice::{
    Class, DomainPattern, Header, Message, Name, Opcode, Question, RData, Rcode, RecordType,
    Resolver, ResourceRecord, SplitDnsPolicy, UpstreamBackend, UpstreamGroupId,
};

/// A minimal in-process fake [`UpstreamBackend`] that always answers with
/// the same fixed address, standing in for a real UDP/TCP backend in this
/// example.
struct FixedAddrBackend {
    addr: Ipv4Addr,
    ttl: u32,
}

#[async_trait]
impl UpstreamBackend for FixedAddrBackend {
    async fn resolve(&self, query: &Message) -> dns_lattice::Result<Message> {
        answer_for(query, self.addr, self.ttl)
    }
}

fn query_for(name: &Name) -> Message {
    Message {
        header: Header {
            id: 0x0001,
            qr: false,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: name.clone(),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    }
}

fn answer_for(query: &Message, addr: Ipv4Addr, ttl: u32) -> dns_lattice::Result<Message> {
    let question = query.questions[0].clone();
    Ok(Message {
        header: Header {
            id: query.header.id,
            qr: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: query.header.recursion_desired,
            recursion_available: true,
            rcode: Rcode::NoError,
        },
        questions: vec![question.clone()],
        answers: vec![ResourceRecord {
            name: question.name,
            rtype: RecordType::A,
            class: Class::In,
            ttl,
            rdata: RData::A(addr),
        }],
        authorities: vec![],
        additionals: vec![],
    })
}

#[tokio::main]
async fn main() {
    let policy = SplitDnsPolicy::builder()
        .rule(
            DomainPattern::suffix(Name::from_ascii("corp.internal").unwrap()),
            UpstreamGroupId::new("corp"),
        )
        .default_group(UpstreamGroupId::new("public"))
        .build();

    let resolver = Resolver::builder(policy)
        .backend(
            UpstreamGroupId::new("corp"),
            FixedAddrBackend {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ttl: 300,
            },
        )
        .backend(
            UpstreamGroupId::new("public"),
            FixedAddrBackend {
                addr: Ipv4Addr::new(93, 184, 216, 34),
                ttl: 300,
            },
        )
        .build();

    let name = Name::from_ascii("host.corp.internal").unwrap();
    let query = query_for(&name);

    let first = resolver
        .resolve(&query)
        .await
        .expect("first resolve succeeds");
    println!("first resolve  (upstream) -> {:?}", first.answers[0].rdata);

    let second = resolver
        .resolve(&query)
        .await
        .expect("second resolve succeeds");
    println!("second resolve (cache)    -> {:?}", second.answers[0].rdata);
    assert_eq!(first, second);

    let unrouted = Name::from_ascii("no-default.example").unwrap();
    let unrouted_query = query_for(&unrouted);
    let no_default_policy = SplitDnsPolicy::builder().build();
    let no_default_resolver = Resolver::builder(no_default_policy).build();
    match no_default_resolver.resolve(&unrouted_query).await {
        Err(dns_lattice::Error::NoRoute) => println!("unrouted query -> Error::NoRoute (expected)"),
        other => panic!("expected Error::NoRoute, got {other:?}"),
    }
}
