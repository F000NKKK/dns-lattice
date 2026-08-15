# dns-lattice-core

Foundational error and result types shared across the DNS Lattice
workspace. This crate has no networking-specific types and no operating
system dependency.

## What it provides

- `Error`, one enum covering every DNS Lattice failure mode (message
  decode/encode, domain pattern parsing, upstream transport, Fake IP pool
  configuration, route-hook validation, and related resolver failures);
- `Result<T>`, the `Result<T, Error>` alias used across the workspace.

Most applications should use these types through the `dns-lattice` crate
rather than depending on this crate directly. Depend on it directly when
implementing a component that needs to return DNS Lattice's error type
without depending on the rest of the facade crate.

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

Stage 0.6 is complete and this crate is part of the `0.6.x` pre-1.0 release
line. Its API may still change while DNS Lattice performs the stage-1.0
public-API freeze and compatibility audit; ordinary stable SemVer guarantees
begin with `1.0.0`.
