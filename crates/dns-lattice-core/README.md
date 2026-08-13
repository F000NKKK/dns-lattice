# dns-lattice-core

Foundational error and result types shared across the DNS Lattice
workspace. This crate has no networking-specific types and no operating
system dependency.

## What it provides

- `Error`, one enum covering every DNS Lattice failure mode (message
  decode/encode, domain pattern parsing, upstream transport, and Fake IP
  pool configuration);
- `Result<T>`, the `Result<T, Error>` alias used across the workspace.

Most applications should use these types through the `dns-lattice` crate
rather than depending on this crate directly. Depend on it directly when
implementing a component that needs to return `dns-lattice`'s error type
without depending on the rest of `dns-lattice`.

## Usage

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

## Status

Pre-0.1 stage: this crate has no stable API yet. Types and variants may
change without notice until `dns-lattice` reaches its first stable release.
