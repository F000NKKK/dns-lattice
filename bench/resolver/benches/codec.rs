//! DNS message decode and encode: dns-lattice next to hickory-proto on
//! identical bytes.
//!
//! The inputs are the [`wire::codec_fixtures`] responses (`a`, `aaaa`,
//! `a10`, `txt`, `nxdomain`), all with an OPT record and answer owners
//! compressed to a pointer, as an upstream would send them.
//!
//! - `decode/<library>/<fixture>`: bytes to an owned message
//!   (`Message::decode` and hickory's `Message::from_vec`). Throughput is
//!   the fixture length.
//! - `encode/<library>/<fixture>`: an already decoded message back to bytes.
//!   `dns-lattice` is `Message::encode` (a fresh buffer), `dns-lattice-into`
//!   is `Message::encode_into` into one reused, cleared buffer, and
//!   `hickory` is `Message::to_vec`. Throughput is the fixture length for
//!   every library, so the numbers stay comparable.
//!
//! The encoded sizes differ: dns-lattice writes names uncompressed and
//! hickory compresses them. The sizes are printed to stderr at start-up.
//!
//! Run with `cargo bench --bench codec` from `bench/resolver`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dns_lattice::model::Message;
use dns_lattice_bench_resolver::wire;
use hickory_proto::op::Message as HkMessage;

fn decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    for fixture in wire::codec_fixtures() {
        let bytes = fixture.bytes.as_slice();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("dns-lattice", fixture.name),
            bytes,
            |b, bytes| b.iter(|| Message::decode(black_box(bytes)).unwrap()),
        );
        group.bench_with_input(
            BenchmarkId::new("hickory", fixture.name),
            bytes,
            |b, bytes| b.iter(|| HkMessage::from_vec(black_box(bytes)).unwrap()),
        );
    }
    group.finish();
}

fn encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    for fixture in wire::codec_fixtures() {
        let dl = Message::decode(&fixture.bytes).unwrap();
        let hk = HkMessage::from_vec(&fixture.bytes).unwrap();
        eprintln!(
            "encode/{}: input {} B, dns-lattice {} B, hickory {} B",
            fixture.name,
            fixture.bytes.len(),
            dl.encode().unwrap().len(),
            hk.to_vec().unwrap().len(),
        );
        group.throughput(Throughput::Bytes(fixture.bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("dns-lattice", fixture.name),
            &dl,
            |b, message| b.iter(|| black_box(message).encode().unwrap()),
        );
        group.bench_with_input(
            BenchmarkId::new("dns-lattice-into", fixture.name),
            &dl,
            |b, message| {
                let mut buf = Vec::with_capacity(4096);
                b.iter(|| {
                    buf.clear();
                    black_box(message).encode_into(&mut buf).unwrap();
                    black_box(buf.len())
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("hickory", fixture.name),
            &hk,
            |b, message| b.iter(|| black_box(message).to_vec().unwrap()),
        );
    }
    group.finish();
}

criterion_group!(benches, decode, encode);
criterion_main!(benches);
