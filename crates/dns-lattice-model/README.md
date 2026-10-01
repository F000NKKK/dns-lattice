<div align="center">

# 🧩 dns-lattice-model

### The DNS Message, Domain Matcher, and Split-DNS Policy Model for DNS Lattice

[![crates.io](https://img.shields.io/crates/v/dns-lattice-model.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice-model)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice-model?cacheSeconds=86400)](https://docs.rs/dns-lattice-model)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/dns-lattice)

[Overview](#-overview) • [Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start)

</div>

---

## 📖 Overview

The DNS message, zone/domain matcher, and policy model for
[DNS Lattice](https://github.com/F000NKKK/dns-lattice). No network I/O, no
operating-system dependency.

> Most applications should use these types through the
> [`dns-lattice`](https://crates.io/crates/dns-lattice) facade crate (as
> `dns_lattice::model`) rather than depending on this crate directly. Depend
> on it directly when implementing a component that needs the DNS model
> without the rest of `dns-lattice`.

## 🌟 Key Features

- ✅ **`message`**: a hand-rolled DNS message model (`Header`, `Question`,
  `ResourceRecord`, `Message`) with wire encode/decode.
- ✅ **`record`**: DNS record types and resource-data (`RecordType`, `Class`,
  `RData`).
- ✅ **`matcher`**: a zone/domain matcher (`DomainPattern`,
  `DomainMatcher<T>`) with deterministic exact/suffix/wildcard precedence.
- ✅ **`policy`**: split-DNS policy types (`UpstreamGroupId`,
  `SplitDnsPolicy`) built on the matcher.

No Cargo features. Its only dependency is
[`dns-lattice-core`](https://crates.io/crates/dns-lattice-core).

## 📦 Installation

```toml
[dependencies]
dns-lattice-model = "1.1.2"
```

## 🎓 Quick Start

```rust
use dns_lattice_model::{DomainPattern, Name, SplitDnsPolicy, UpstreamGroupId};

let policy = SplitDnsPolicy::builder()
    .rule(DomainPattern::parse("corp.internal").unwrap(), UpstreamGroupId::new("corp"))
    .default_group(UpstreamGroupId::new("public"))
    .build();

let host = Name::from_ascii("git.corp.internal").unwrap();
assert_eq!(policy.resolve_group(&host), Some(&UpstreamGroupId::new("corp")));

let other = Name::from_ascii("example.org").unwrap();
assert_eq!(policy.resolve_group(&other), Some(&UpstreamGroupId::new("public")));
```

`DomainPattern::parse` turns `"*.example.com"` into a wildcard pattern and
anything else into a suffix pattern; `DomainPattern::exact` matches one name
only.

## 🎯 Matching Precedence

Matching is case-insensitive. An exact rule beats every suffix and wildcard
rule. Between suffix rules, or between wildcard rules, the rule with the most
labels wins. Equal kind and label-count ties keep insertion order: the first
inserted rule wins.

## 🧪 Hardening

Stage-0.6 hardening added deterministic property-style verification around
message parsing/compression bounds and matcher precedence without introducing
network or OS responsibilities into this crate.

## 📌 Status

**Stable `1.x` releases are published** on crates.io. The public model is
frozen; ordinary SemVer guarantees apply within the `1.x` line — a breaking
change requires an explicit major version bump.

## 📖 Documentation

- **API reference**: [docs.rs/dns-lattice-model](https://docs.rs/dns-lattice-model)
- **Project**: [github.com/F000NKKK/dns-lattice](https://github.com/F000NKKK/dns-lattice)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE).
