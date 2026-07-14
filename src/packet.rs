//! The packet header and its codec.
//!
//! A packet is a two-byte header, one or two address fields, a context byte, and a
//! payload:
//!
//! ```text
//! byte 0   flags
//! byte 1   hops
//! 2..18    destination address hash (16)
//! [18..34] transport address hash (16), only when header_type == Type2]
//! next     context byte
//! rest     payload
//! ```
//!
//! Flag byte 0, most significant bit first:
//!
//! ```text
//! bit 7     IFAC flag
//! bit 6     header type   (0 = one address field, 1 = two)
//! bit 5     context flag  (announce: a ratchet key is present)
//! bit 4     propagation   (0 = broadcast, 1 = transport)
//! bits 3..2 destination type (single=0, group=1, plain=2, link=3)
//! bits 1..0 packet type      (data=0, announce=1, link request=2, proof=3)
//! ```
//!
//! Verified against RNS 1.3.8. A plain announce has flags `0x01`; the same announce with
//! ratchets enabled has `0x21`, differing only in bit 5. `HEADER_MINSIZE = 19` = 2 + 16 + 1
//! and `HEADER_MAXSIZE = 35` = 2 + 16 + 16 + 1 corroborate the address-field layout.

use crate::hash::{ADDRESS_HASH_LEN, AddressHash};
use crate::{Error, Result};

/// Smallest possible header: flags, hops, one address, context.
pub const HEADER_MIN_LEN: usize = 2 + ADDRESS_HASH_LEN + 1;

/// Largest possible header: as above, with a second address field.
pub const HEADER_MAX_LEN: usize = 2 + ADDRESS_HASH_LEN * 2 + 1;

/// Maximum size of a whole packet on the wire.
pub const MTU: usize = 500;

/// What kind of packet this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Data,
    Announce,
    LinkRequest,
    Proof,
}

impl PacketType {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::Data,
            1 => Self::Announce,
            2 => Self::LinkRequest,
            _ => Self::Proof,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Announce => 1,
            Self::LinkRequest => 2,
            Self::Proof => 3,
        }
    }
}

/// What kind of destination the address field names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationType {
    Single,
    Group,
    Plain,
    Link,
}

impl DestinationType {
    fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0 => Self::Single,
            1 => Self::Group,
            2 => Self::Plain,
            _ => Self::Link,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::Single => 0,
            Self::Group => 1,
            Self::Plain => 2,
            Self::Link => 3,
        }
    }
}

/// Whether the packet carries one address field or two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderType {
    /// One address field: the destination.
    Type1,
    /// Two address fields: a transport hop, then the destination.
    Type2,
}

/// How the packet propagates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Propagation {
    Broadcast,
    Transport,
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub ifac: bool,
    pub header_type: HeaderType,
    /// Bit 5. On an announce this means "a ratchet key is present in the payload".
    pub context_flag: bool,
    pub propagation: Propagation,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
    pub hops: u8,
    /// The second address field, present only when `header_type == Type2`.
    pub transport: Option<AddressHash>,
    pub destination: AddressHash,
    pub context: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Decode a packet from the wire.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_MIN_LEN {
            return Err(Error::Truncated);
        }

        let flags = bytes[0];
        let ifac = flags & 0b1000_0000 != 0;
        let header_type = if flags & 0b0100_0000 != 0 {
            HeaderType::Type2
        } else {
            HeaderType::Type1
        };
        let context_flag = flags & 0b0010_0000 != 0;
        let propagation = if flags & 0b0001_0000 != 0 {
            Propagation::Transport
        } else {
            Propagation::Broadcast
        };
        let destination_type = DestinationType::from_bits(flags >> 2);
        let packet_type = PacketType::from_bits(flags);
        let hops = bytes[1];

        let mut off = 2;
        let transport = match header_type {
            HeaderType::Type2 => {
                let h = AddressHash::from_slice(&bytes[off..]).ok_or(Error::Truncated)?;
                off += ADDRESS_HASH_LEN;
                Some(h)
            }
            HeaderType::Type1 => None,
        };

        let destination = AddressHash::from_slice(&bytes[off..]).ok_or(Error::Truncated)?;
        off += ADDRESS_HASH_LEN;

        let context = *bytes.get(off).ok_or(Error::Truncated)?;
        off += 1;

        Ok(Self {
            ifac,
            header_type,
            context_flag,
            propagation,
            destination_type,
            packet_type,
            hops,
            transport,
            destination,
            context,
            payload: bytes[off..].to_vec(),
        })
    }

    /// Encode a packet for the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = 0u8;
        if self.ifac {
            flags |= 0b1000_0000;
        }
        if matches!(self.header_type, HeaderType::Type2) {
            flags |= 0b0100_0000;
        }
        if self.context_flag {
            flags |= 0b0010_0000;
        }
        if matches!(self.propagation, Propagation::Transport) {
            flags |= 0b0001_0000;
        }
        flags |= self.destination_type.to_bits() << 2;
        flags |= self.packet_type.to_bits();

        let mut out = Vec::with_capacity(HEADER_MAX_LEN + self.payload.len());
        out.push(flags);
        out.push(self.hops);
        if let Some(t) = self.transport {
            out.extend_from_slice(t.as_slice());
        }
        out.extend_from_slice(self.destination.as_slice());
        out.push(self.context);
        out.extend_from_slice(&self.payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_flags_round_trip() {
        // 0x01: announce, single, broadcast, one address field, no context flag.
        let p = Packet::decode(&{
            let mut v = vec![0x01, 0x00];
            v.extend_from_slice(&[0xAA; 16]);
            v.push(0x00);
            v.extend_from_slice(b"payload");
            v
        })
        .unwrap();
        assert_eq!(p.packet_type, PacketType::Announce);
        assert_eq!(p.destination_type, DestinationType::Single);
        assert_eq!(p.header_type, HeaderType::Type1);
        assert_eq!(p.propagation, Propagation::Broadcast);
        assert!(!p.context_flag);
        assert!(!p.ifac);
        assert_eq!(p.payload, b"payload");
        assert_eq!(p.encode()[0], 0x01);
    }

    #[test]
    fn context_flag_is_bit_five() {
        let mut v = vec![0x21, 0x00];
        v.extend_from_slice(&[0xAA; 16]);
        v.push(0x00);
        let p = Packet::decode(&v).unwrap();
        assert!(p.context_flag);
        assert_eq!(p.packet_type, PacketType::Announce);
        assert_eq!(p.encode()[0], 0x21);
    }

    #[test]
    fn truncated_input_is_an_error() {
        assert!(Packet::decode(&[0x01, 0x00]).is_err());
    }
}
