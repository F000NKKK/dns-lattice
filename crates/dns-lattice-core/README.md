<div align="center">

# 🧱 dns-lattice-core

### Shared Error and Result Types for DNS Lattice

[![crates.io](https://img.shields.io/crates/v/dns-lattice-core.svg?cacheSeconds=86400)](https://crates.io/crates/dns-lattice-core)
[![docs.rs](https://img.shields.io/docsrs/dns-lattice-core?cacheSeconds=86400)](https://docs.rs/dns-lattice-core)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-lightgrey.svg)](https://github.com/F000NKKK/dns-lattice)

[Overview](#-overview) • [Features](#-key-features)
• [Installation](#-installation) • [Quick Start](#-quick-start)

</div>

---

## 📖 Overview

The foundation crate of [DNS Lattice](https://github.com/F000NKKK/dns-lattice):
foundational error and result types shared across the DNS Lattice
workspace. This crate has no networking-specific types and no operating
system dependency.

> Most applications should use these types through the
> [`dns-lattice`](https://crates.io/crates/dns-lattice) crate rather than
> depending on this crate directly. Depend on it directly when implementing a
> component that needs to return DNS Lattice's error type without depending
> on the rest of the facade crate.

## 🌟 Key Features

- ✅ **`Error`**: one enum covering every DNS Lattice failure mode (message
  decode/encode, domain pattern parsing, upstream transport, Fake IP pool
  configuration, route-hook validation, and related resolver failures);
- ✅ **`Result<T>`**: the `Result<T, Error>` alias used across the workspace.

No Cargo features and no dependencies.

## 📦 Installation

```toml
[dependencies]
dns-lattice-core = "1.1"
```

## 🎓 Quick Start

```rust
use dns_lattice_core::{Error, Result};

fn decode_class(raw: u16) -> Result<u16> {
    match raw {
        1 | 3 => Ok(raw),
        other => Err(Error::InvalidClass(other)),
    }
}

assert!(decode_class(1).is_ok());
assert!(decode_class(9999).is_err());
```

## 📌 Status

**Stable `1.x` releases are published** on crates.io. The public API is
frozen; ordinary SemVer guarantees apply within the `1.x` line — a breaking
change requires an explicit major version bump.

## 📖 Documentation

- **API reference**: [docs.rs/dns-lattice-core](https://docs.rs/dns-lattice-core)
- **Project**: [github.com/F000NKKK/dns-lattice](https://github.com/F000NKKK/dns-lattice)

## 📄 License

Licensed under the [Mozilla Public License 2.0](https://github.com/F000NKKK/dns-lattice/blob/main/LICENSE).
