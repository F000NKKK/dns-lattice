//! DNS record types and resource-data (`RDATA`) encode/decode.

use std::net::{Ipv4Addr, Ipv6Addr};

use dns_lattice_core::{Error, Result};

use super::message::{decode_name, encode_name, read_u16, read_u32, write_u16, write_u32};
use super::Name;

/// A DNS resource record type (RFC 1035 §3.2.2 and later RFCs).
///
/// Only the types this crate's stage-0.1 consumers need are enumerated
/// individually; every other value round-trips through [`Other`](RecordType::Other).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// A host address (IPv4).
    A,
    /// A host address (IPv6).
    Aaaa,
    /// The canonical name for an alias.
    Cname,
    /// A domain name pointer (reverse lookup).
    Ptr,
    /// An authoritative name server.
    Ns,
    /// Text strings.
    Txt,
    /// Mail exchange.
    Mx,
    /// Start of a zone of authority.
    Soa,
    /// Any record type not enumerated above, carrying its raw wire value.
    Other(u16),
}

impl RecordType {
    pub(crate) fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::Ns,
            5 => RecordType::Cname,
            6 => RecordType::Soa,
            12 => RecordType::Ptr,
            15 => RecordType::Mx,
            16 => RecordType::Txt,
            28 => RecordType::Aaaa,
            other => RecordType::Other(other),
        }
    }

    pub(crate) fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
            RecordType::Other(value) => value,
        }
    }
}

/// A DNS record class (RFC 1035 §3.2.4). `0` is reserved and rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// The Internet.
    In,
    /// Chaos.
    Ch,
    /// Any class value not enumerated above, carrying its raw wire value.
    Other(u16),
}

impl Class {
    pub(crate) fn from_u16(value: u16) -> Result<Self> {
        match value {
            0 => Err(Error::InvalidClass(0)),
            1 => Ok(Class::In),
            3 => Ok(Class::Ch),
            other => Ok(Class::Other(other)),
        }
    }

    pub(crate) fn to_u16(self) -> u16 {
        match self {
            Class::In => 1,
            Class::Ch => 3,
            Class::Other(value) => value,
        }
    }
}

/// The resource-data payload of a [`ResourceRecord`](super::message::ResourceRecord),
/// distinguished by [`RecordType`].
///
/// An [`RData::Unknown`] carries any record type this crate does not
/// interpret; decoding an unrecognized `RTYPE` never fails, since a
/// conformant parser must tolerate record types it does not act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// [`RecordType::A`].
    A(Ipv4Addr),
    /// [`RecordType::Aaaa`].
    Aaaa(Ipv6Addr),
    /// [`RecordType::Cname`].
    Cname(Name),
    /// [`RecordType::Ptr`].
    Ptr(Name),
    /// [`RecordType::Ns`].
    Ns(Name),
    /// [`RecordType::Txt`]: one entry per character-string.
    Txt(Vec<Vec<u8>>),
    /// [`RecordType::Mx`].
    Mx {
        /// Preference given to this exchange; lower values are preferred.
        preference: u16,
        /// The mail exchange host.
        exchange: Name,
    },
    /// [`RecordType::Soa`].
    Soa {
        /// The primary name server for the zone.
        mname: Name,
        /// The mailbox of the zone's administrator.
        rname: Name,
        /// The zone's version number.
        serial: u32,
        /// Seconds before the zone should be refreshed.
        refresh: u32,
        /// Seconds before a failed refresh should be retried.
        retry: u32,
        /// Seconds after which the zone is no longer authoritative.
        expire: u32,
        /// The negative-caching TTL (RFC 2308).
        minimum: u32,
    },
    /// Any record type not enumerated above.
    Unknown {
        /// The raw wire `RTYPE` value.
        rtype: u16,
        /// The raw `RDATA` bytes, unparsed.
        data: Vec<u8>,
    },
}

impl RData {
    pub(crate) fn record_type(&self) -> RecordType {
        match self {
            RData::A(_) => RecordType::A,
            RData::Aaaa(_) => RecordType::Aaaa,
            RData::Cname(_) => RecordType::Cname,
            RData::Ptr(_) => RecordType::Ptr,
            RData::Ns(_) => RecordType::Ns,
            RData::Txt(_) => RecordType::Txt,
            RData::Mx { .. } => RecordType::Mx,
            RData::Soa { .. } => RecordType::Soa,
            RData::Unknown { rtype, .. } => RecordType::Other(*rtype),
        }
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        match self {
            RData::A(addr) => buf.extend_from_slice(&addr.octets()),
            RData::Aaaa(addr) => buf.extend_from_slice(&addr.octets()),
            RData::Cname(name) | RData::Ptr(name) | RData::Ns(name) => encode_name(name, buf)?,
            RData::Txt(strings) => {
                for s in strings {
                    if s.len() > 255 {
                        return Err(Error::LabelTooLong { offset: buf.len() });
                    }
                    buf.push(s.len() as u8);
                    buf.extend_from_slice(s);
                }
            }
            RData::Mx {
                preference,
                exchange,
            } => {
                write_u16(buf, *preference);
                encode_name(exchange, buf)?;
            }
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                encode_name(mname, buf)?;
                encode_name(rname, buf)?;
                write_u32(buf, *serial);
                write_u32(buf, *refresh);
                write_u32(buf, *retry);
                write_u32(buf, *expire);
                write_u32(buf, *minimum);
            }
            RData::Unknown { data, .. } => buf.extend_from_slice(data),
        }
        Ok(())
    }

    pub(crate) fn decode(buf: &[u8], pos: &mut usize, rtype: RecordType, rdlength: usize) -> Result<Self> {
        let start = *pos;
        let end = start
            .checked_add(rdlength)
            .filter(|&end| end <= buf.len())
            .ok_or(Error::Truncated { len: buf.len() })?;

        let rdata = match rtype {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(Error::RDataLengthMismatch {
                        declared: rdlength as u16,
                    });
                }
                let addr = Ipv4Addr::new(buf[start], buf[start + 1], buf[start + 2], buf[start + 3]);
                *pos += 4;
                RData::A(addr)
            }
            RecordType::Aaaa => {
                if rdlength != 16 {
                    return Err(Error::RDataLengthMismatch {
                        declared: rdlength as u16,
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[start..start + 16]);
                *pos += 16;
                RData::Aaaa(Ipv6Addr::from(octets))
            }
            RecordType::Cname => RData::Cname(decode_checked_name(buf, pos, start, rdlength)?),
            RecordType::Ptr => RData::Ptr(decode_checked_name(buf, pos, start, rdlength)?),
            RecordType::Ns => RData::Ns(decode_checked_name(buf, pos, start, rdlength)?),
            RecordType::Txt => {
                let mut strings = Vec::new();
                let mut p = start;
                while p < end {
                    let len = buf[p] as usize;
                    p += 1;
                    if p + len > end {
                        return Err(Error::RDataLengthMismatch {
                            declared: rdlength as u16,
                        });
                    }
                    strings.push(buf[p..p + len].to_vec());
                    p += len;
                }
                *pos = end;
                RData::Txt(strings)
            }
            RecordType::Mx => {
                let preference = read_u16(buf, pos)?;
                let exchange = decode_name(buf, pos)?;
                if *pos - start != rdlength {
                    return Err(Error::RDataLengthMismatch {
                        declared: rdlength as u16,
                    });
                }
                RData::Mx {
                    preference,
                    exchange,
                }
            }
            RecordType::Soa => {
                let mname = decode_name(buf, pos)?;
                let rname = decode_name(buf, pos)?;
                let serial = read_u32(buf, pos)?;
                let refresh = read_u32(buf, pos)?;
                let retry = read_u32(buf, pos)?;
                let expire = read_u32(buf, pos)?;
                let minimum = read_u32(buf, pos)?;
                if *pos - start != rdlength {
                    return Err(Error::RDataLengthMismatch {
                        declared: rdlength as u16,
                    });
                }
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            RecordType::Other(value) => {
                let data = buf[start..end].to_vec();
                *pos = end;
                RData::Unknown { rtype: value, data }
            }
        };
        Ok(rdata)
    }
}

fn decode_checked_name(buf: &[u8], pos: &mut usize, start: usize, rdlength: usize) -> Result<Name> {
    let name = decode_name(buf, pos)?;
    if *pos - start != rdlength {
        return Err(Error::RDataLengthMismatch {
            declared: rdlength as u16,
        });
    }
    Ok(name)
}
