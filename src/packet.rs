//! The MeshCore outer packet codec.
//!
//! Wire layout (all little-endian where multi-byte):
//!
//! ```text
//! [header u8] [transport_codes u16 x2, only when the route type carries them]
//! [path_len u8] [path bytes] [payload ... to end of frame]
//! ```
//!
//! The payload has no length field of its own: it runs to the end of the
//! radio frame, so decoding needs the frame length. `path_len` packs a hash
//! size and count: size = `(path_len >> 6) + 1` (a size of 4 is reserved),
//! count = `path_len & 63`.
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use sha2::{Digest, Sha256};

/// Route type: flood via transport codes.
pub const ROUTE_TRANSPORT_FLOOD: u8 = 0x00;
/// Route type: flood, building up `path` as it goes.
pub const ROUTE_FLOOD: u8 = 0x01;
/// Route type: direct, `path` supplied by sender.
pub const ROUTE_DIRECT: u8 = 0x02;
/// Route type: direct via transport codes.
pub const ROUTE_TRANSPORT_DIRECT: u8 = 0x03;

/// Payload types (4-bit field).
pub mod payload_type {
    pub const REQ: u8 = 0x00;
    pub const RESPONSE: u8 = 0x01;
    pub const TXT_MSG: u8 = 0x02;
    pub const ACK: u8 = 0x03;
    pub const ADVERT: u8 = 0x04;
    pub const GRP_TXT: u8 = 0x05;
    pub const GRP_DATA: u8 = 0x06;
    pub const ANON_REQ: u8 = 0x07;
    pub const PATH: u8 = 0x08;
    pub const TRACE: u8 = 0x09;
    pub const MULTIPART: u8 = 0x0A;
    pub const CONTROL: u8 = 0x0B;
    pub const RAW_CUSTOM: u8 = 0x0F;
}

/// Truncated packet-hash length (SHA256 prefix).
pub const HASH_SIZE: usize = 8;
/// Maximum payload bytes in one packet.
pub const MAX_PAYLOAD: usize = 184;
/// Maximum path bytes in one packet.
pub const MAX_PATH: usize = 64;
/// Ed25519 public key length.
pub const PUB_KEY_SIZE: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_SIZE: usize = 64;
/// AES cipher key/block length.
pub const CIPHER_KEY_SIZE: usize = 16;
/// Truncated MAC length on encrypted payloads.
pub const CIPHER_MAC_SIZE: usize = 2;

const ROUTE_MASK: u8 = 0x03;
const TYPE_SHIFT: u8 = 2;
const TYPE_MASK: u8 = 0x0F;
const VER_SHIFT: u8 = 6;

/// A decoded MeshCore packet (outer layer; payload is opaque here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: u8,
    /// Present on the wire only for `ROUTE_TRANSPORT_*` route types.
    pub transport_codes: [u16; 2],
    /// Raw `path_len` byte (packed hash size + count).
    pub path_len: u8,
    pub path: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(route: u8, ptype: u8) -> Self {
        Packet {
            header: (route & ROUTE_MASK) | ((ptype & TYPE_MASK) << TYPE_SHIFT),
            transport_codes: [0; 2],
            path_len: 0,
            path: Vec::new(),
            payload: Vec::new(),
        }
    }

    pub fn route_type(&self) -> u8 {
        self.header & ROUTE_MASK
    }

    pub fn payload_type(&self) -> u8 {
        (self.header >> TYPE_SHIFT) & TYPE_MASK
    }

    pub fn payload_ver(&self) -> u8 {
        self.header >> VER_SHIFT
    }

    pub fn is_flood(&self) -> bool {
        matches!(self.route_type(), ROUTE_FLOOD | ROUTE_TRANSPORT_FLOOD)
    }

    pub fn has_transport_codes(&self) -> bool {
        matches!(
            self.route_type(),
            ROUTE_TRANSPORT_FLOOD | ROUTE_TRANSPORT_DIRECT
        )
    }

    fn path_hash_size(path_len: u8) -> usize {
        ((path_len >> 6) + 1) as usize
    }

    fn path_hash_count(path_len: u8) -> usize {
        (path_len & 63) as usize
    }

    fn path_byte_len(path_len: u8) -> usize {
        Self::path_hash_size(path_len) * Self::path_hash_count(path_len)
    }

    /// A `path_len` is valid when hash size is not the reserved 4 and the
    /// packed byte length fits `MAX_PATH`.
    pub fn is_valid_path_len(path_len: u8) -> bool {
        Self::path_hash_size(path_len) != 4 && Self::path_byte_len(path_len) <= MAX_PATH
    }

    /// Truncated SHA256 identifying this packet for dedup: hashes the payload
    /// type, then (for TRACE only) the raw `path_len`, then the payload.
    pub fn packet_hash(&self) -> [u8; HASH_SIZE] {
        let mut sha = Sha256::new();
        sha.update([self.payload_type()]);
        if self.payload_type() == payload_type::TRACE {
            // TRACE packets can revisit a node on the return path; the
            // evolving path_len keeps their hashes distinct.
            sha.update([self.path_len, 0]);
        }
        sha.update(&self.payload);
        let full = sha.finalize();
        let mut out = [0u8; HASH_SIZE];
        out.copy_from_slice(&full[..HASH_SIZE]);
        out
    }

    /// Encoded wire length.
    pub fn raw_len(&self) -> usize {
        2 + self.path.len() + self.payload.len() + if self.has_transport_codes() { 4 } else { 0 }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.raw_len());
        out.push(self.header);
        if self.has_transport_codes() {
            out.extend_from_slice(&self.transport_codes[0].to_le_bytes());
            out.extend_from_slice(&self.transport_codes[1].to_le_bytes());
        }
        out.push(self.path_len);
        out.extend_from_slice(&self.path);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode one packet from a whole radio frame. The payload runs to the
    /// end of `src`, so the caller must pass exactly one frame.
    pub fn decode(src: &[u8]) -> Option<Packet> {
        let mut i = 0;
        let header = *src.get(i)?;
        i += 1;

        let route = header & ROUTE_MASK;
        let mut transport_codes = [0u16; 2];
        if matches!(route, ROUTE_TRANSPORT_FLOOD | ROUTE_TRANSPORT_DIRECT) {
            let raw = src.get(i..i + 4)?;
            transport_codes[0] = u16::from_le_bytes([raw[0], raw[1]]);
            transport_codes[1] = u16::from_le_bytes([raw[2], raw[3]]);
            i += 4;
        }

        let path_len = *src.get(i)?;
        i += 1;
        if !Self::is_valid_path_len(path_len) {
            return None;
        }
        let bl = Self::path_byte_len(path_len);
        let path = src.get(i..i + bl)?.to_vec();
        i += bl;

        if i >= src.len() {
            return None; // upstream rejects empty payloads
        }
        let payload = src[i..].to_vec();
        if payload.len() > MAX_PAYLOAD {
            return None;
        }

        Some(Packet {
            header,
            transport_codes,
            path_len,
            path,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_direct_no_transport() {
        let mut p = Packet::new(ROUTE_DIRECT, payload_type::TXT_MSG);
        p.path_len = 3; // three 1-byte hashes
        p.path = vec![0xAA, 0xBB, 0xCC];
        p.payload = b"hello mesh".to_vec();
        let wire = p.encode();
        assert_eq!(wire.len(), p.raw_len());
        let q = Packet::decode(&wire).unwrap();
        assert_eq!(p, q);
        assert_eq!(q.route_type(), ROUTE_DIRECT);
        assert_eq!(q.payload_type(), payload_type::TXT_MSG);
        assert!(!q.has_transport_codes());
    }

    #[test]
    fn roundtrip_transport_codes() {
        let mut p = Packet::new(ROUTE_TRANSPORT_FLOOD, payload_type::ACK);
        p.transport_codes = [0x1234, 0xBEEF];
        p.payload = vec![1, 2, 3, 4];
        let wire = p.encode();
        // header + 4 transport bytes + path_len + payload
        assert_eq!(wire.len(), 1 + 4 + 1 + 4);
        // transport codes are little-endian on the wire
        assert_eq!(&wire[1..5], &[0x34, 0x12, 0xEF, 0xBE]);
        let q = Packet::decode(&wire).unwrap();
        assert_eq!(p, q);
        assert!(q.is_flood());
    }

    #[test]
    fn reserved_hash_size_rejected() {
        // hash size 4 (top bits 0b11) is reserved
        let path_len = 0b1100_0001;
        assert!(!Packet::is_valid_path_len(path_len));
        let frame = [ROUTE_DIRECT, path_len, 0, 0, 0, 0, 9, 9];
        assert!(Packet::decode(&frame).is_none());
    }

    #[test]
    fn empty_payload_rejected() {
        let mut p = Packet::new(ROUTE_FLOOD, payload_type::ADVERT);
        p.payload = vec![7];
        let mut wire = p.encode();
        assert!(Packet::decode(&wire).is_some());
        wire.pop(); // strip the payload entirely
        assert!(Packet::decode(&wire).is_none());
    }

    #[test]
    fn truncated_transport_codes_rejected() {
        let frame = [ROUTE_TRANSPORT_DIRECT, 0x11]; // needs 4 bytes of codes
        assert!(Packet::decode(&frame).is_none());
    }

    #[test]
    fn two_byte_path_hashes() {
        let mut p = Packet::new(ROUTE_FLOOD, payload_type::PATH);
        p.path_len = 0b0100_0010; // size 2, count 2 -> 4 path bytes
        p.path = vec![1, 2, 3, 4];
        p.payload = vec![0xFF];
        let q = Packet::decode(&p.encode()).unwrap();
        assert_eq!(q.path, vec![1, 2, 3, 4]);
    }

    #[test]
    fn hash_distinguishes_type_not_route() {
        let mut a = Packet::new(ROUTE_FLOOD, payload_type::TXT_MSG);
        a.payload = b"same".to_vec();
        let mut b = a.clone();
        b.header = (b.header & !0x03) | ROUTE_DIRECT; // route change only
        assert_eq!(a.packet_hash(), b.packet_hash());
        let mut c = Packet::new(ROUTE_FLOOD, payload_type::GRP_TXT);
        c.payload = b"same".to_vec();
        assert_ne!(a.packet_hash(), c.packet_hash());
    }
}
