use std::fmt;

/// The single error type surfaced across the DNS Lattice workspace.
///
/// DNS message and domain-pattern operations return `Result<T, Error>` —
/// never a bare `String`, panic, or ad hoc per-module error type. See
/// `ARCHITECTURE.md`'s cross-cutting concerns for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The message buffer ended before a length-prefixed field or a
    /// declared record/section could be fully read.
    Truncated {
        /// The number of bytes actually available.
        len: usize,
    },
    /// A DNS name compression pointer is out of bounds, or two pointers
    /// form a loop.
    BadNamePointer {
        /// The byte offset of the offending pointer.
        offset: usize,
    },
    /// A name label's length byte exceeds the 63-byte maximum (RFC 1035
    /// §2.3.4).
    LabelTooLong {
        /// The byte offset of the offending label.
        offset: usize,
    },
    /// An encoded or decoded name exceeds the 255-byte maximum (RFC 1035
    /// §2.3.4).
    NameTooLong,
    /// A name label was empty (two consecutive dots) or contained bytes
    /// not permitted in that position.
    InvalidName,
    /// The header's declared section count does not match the number of
    /// records actually present after parsing.
    CountMismatch,
    /// A resource record's declared `RDLENGTH` does not match the number
    /// of bytes actually available or consumed for its `RDATA`.
    RDataLengthMismatch {
        /// The declared `RDLENGTH` value.
        declared: u16,
    },
    /// A question or resource record's class value is not a value this
    /// crate recognizes as well-formed.
    InvalidClass(u16),
    /// Encoding a message would exceed the 65535-byte maximum a DNS
    /// message can address.
    MessageTooLong,
    /// A domain pattern's wildcard label (`*`) appeared somewhere other
    /// than the leftmost position.
    WildcardPosition,
    /// No split-DNS rule matched the queried name and no default upstream
    /// group is configured.
    NoRoute,
    /// An upstream backend did not produce a response within its
    /// configured timeout (stage 0.3, `upstream::UpstreamBackend`).
    Timeout,
    /// An upstream backend's transport (socket connect/send/receive)
    /// failed. Carries a human-readable description of the underlying I/O
    /// error; not `PartialEq`-sensitive to that error's exact kind since
    /// `std::io::Error` is not itself comparable (stage 0.3,
    /// `upstream::UpstreamBackend`).
    Transport(String),
    /// A TLS handshake, certificate validation, or hostname verification
    /// failure while establishing or maintaining an encrypted upstream
    /// connection (stage 0.3, DoT `upstream::DotBackend`/DoH
    /// `upstream::DohBackend`). Carries a human-readable description; not
    /// `PartialEq`-sensitive to the underlying TLS library's exact error
    /// type, matching `Transport`'s existing precedent.
    Tls(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { len } => write!(f, "message truncated: {len} bytes available"),
            Error::BadNamePointer { offset } => {
                write!(f, "invalid name compression pointer at offset {offset}")
            }
            Error::LabelTooLong { offset } => {
                write!(f, "label exceeds 63 bytes at offset {offset}")
            }
            Error::NameTooLong => write!(f, "name exceeds 255 bytes"),
            Error::InvalidName => write!(f, "invalid domain name"),
            Error::CountMismatch => {
                write!(f, "header section count does not match parsed records")
            }
            Error::RDataLengthMismatch { declared } => {
                write!(
                    f,
                    "rdlength {declared} does not match available rdata bytes"
                )
            }
            Error::InvalidClass(class) => write!(f, "invalid class value {class}"),
            Error::MessageTooLong => write!(f, "encoded message would exceed 65535 bytes"),
            Error::WildcardPosition => {
                write!(f, "wildcard label may only appear as the leftmost label")
            }
            Error::NoRoute => write!(
                f,
                "no split-dns rule matched and no default upstream group is configured"
            ),
            Error::Timeout => write!(f, "upstream backend timed out"),
            Error::Transport(message) => write!(f, "upstream transport error: {message}"),
            Error::Tls(message) => write!(f, "upstream tls error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_stable_non_empty_display_message() {
        let cases = [
            (
                Error::Truncated { len: 3 },
                "message truncated: 3 bytes available",
            ),
            (
                Error::BadNamePointer { offset: 12 },
                "invalid name compression pointer at offset 12",
            ),
            (
                Error::LabelTooLong { offset: 5 },
                "label exceeds 63 bytes at offset 5",
            ),
            (Error::NameTooLong, "name exceeds 255 bytes"),
            (Error::InvalidName, "invalid domain name"),
            (
                Error::CountMismatch,
                "header section count does not match parsed records",
            ),
            (
                Error::RDataLengthMismatch { declared: 200 },
                "rdlength 200 does not match available rdata bytes",
            ),
            (Error::InvalidClass(9999), "invalid class value 9999"),
            (
                Error::MessageTooLong,
                "encoded message would exceed 65535 bytes",
            ),
            (
                Error::WildcardPosition,
                "wildcard label may only appear as the leftmost label",
            ),
            (
                Error::NoRoute,
                "no split-dns rule matched and no default upstream group is configured",
            ),
            (Error::Timeout, "upstream backend timed out"),
            (
                Error::Transport("connection refused".to_string()),
                "upstream transport error: connection refused",
            ),
            (
                Error::Tls("certificate expired".to_string()),
                "upstream tls error: certificate expired",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_std_error<E: std::error::Error>(_: &E) {}
        assert_std_error(&Error::NameTooLong);
    }
}
