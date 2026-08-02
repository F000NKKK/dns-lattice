//! Builds a static split-DNS policy and resolves a few names against it.
//!
//! Run with: `cargo run -p dns-lattice --example split_dns_policy`

use dns_lattice::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};

fn main() {
    let policy = SplitDnsPolicy::builder()
        .rule(
            DomainPattern::suffix(Name::from_ascii("corp.internal").unwrap()),
            UpstreamGroupId::new("corp"),
        )
        .rule(
            DomainPattern::wildcard(Name::from_ascii("cdn.example.com").unwrap()),
            UpstreamGroupId::new("cdn"),
        )
        .default_group(UpstreamGroupId::new("public"))
        .build();

    for candidate in [
        "host.corp.internal",
        "assets.cdn.example.com",
        "cdn.example.com",
        "example.org",
    ] {
        let name = Name::from_ascii(candidate).unwrap();
        let group = policy.resolve_group(&name);
        println!("{candidate:<28} -> {group:?}");
    }
}
