//! LoRa transport framing and channel-payload cryptography.
//!
//! This module stops at the transport boundary. It can name fields published in
//! the radio-header specification and can encrypt or decrypt payload bytes.
//! [`crate::application`] interprets the application envelope separately.

use aes::{Aes128, Aes256};
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Number of cleartext bytes before the encrypted payload.
pub const HEADER_LEN: usize = 16;
/// Largest payload published for the LoRa transport, excluding the header.
pub const MAX_PAYLOAD_LEN: usize = 237;
/// Destination value used for a broadcast.
pub const BROADCAST_DESTINATION: u32 = u32::MAX;

const HOP_MASK: u8 = 0b0000_0111;
const WANT_ACK_MASK: u8 = 0b0000_1000;
const VIA_MQTT_MASK: u8 = 0b0001_0000;
const HOP_START_SHIFT: u8 = 5;

/// A channel key after any channel-configuration expansion has been applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKey {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
}

/// The fixed 16-byte cleartext radio header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub destination: u32,
    pub source: u32,
    pub packet_id: u32,
    pub hop_limit: u8,
    pub want_ack: bool,
    pub via_mqtt: bool,
    pub hop_start: u8,
    pub channel_hash: u8,
    pub next_hop: u8,
    pub relay_node: u8,
}

impl Header {
    /// Parse the cleartext header at the beginning of a radio packet.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < HEADER_LEN {
            return Err(TransportError::TruncatedHeader {
                actual: bytes.len(),
            });
        }

        let flags = bytes[12];
        Ok(Self {
            destination: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            source: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            packet_id: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            hop_limit: flags & HOP_MASK,
            want_ack: flags & WANT_ACK_MASK != 0,
            via_mqtt: flags & VIA_MQTT_MASK != 0,
            hop_start: flags >> HOP_START_SHIFT,
            channel_hash: bytes[13],
            next_hop: bytes[14],
            relay_node: bytes[15],
        })
    }

    /// Encode the header exactly as it is transmitted over LoRa.
    pub fn encode(self) -> Result<[u8; HEADER_LEN], TransportError> {
        if self.hop_limit > HOP_MASK {
            return Err(TransportError::HopLimit(self.hop_limit));
        }
        if self.hop_start > HOP_MASK {
            return Err(TransportError::HopStart(self.hop_start));
        }

        let mut out = [0; HEADER_LEN];
        out[0..4].copy_from_slice(&self.destination.to_le_bytes());
        out[4..8].copy_from_slice(&self.source.to_le_bytes());
        out[8..12].copy_from_slice(&self.packet_id.to_le_bytes());
        out[12] = self.hop_limit
            | u8::from(self.want_ack) * WANT_ACK_MASK
            | u8::from(self.via_mqtt) * VIA_MQTT_MASK
            | self.hop_start << HOP_START_SHIFT;
        out[13] = self.channel_hash;
        out[14] = self.next_hop;
        out[15] = self.relay_node;
        Ok(out)
    }

    /// Return a managed-flooding header for one further hop.
    ///
    /// The source and packet ID remain unchanged because together they identify
    /// the encrypted payload and construct its nonce. A zero hop limit cannot be
    /// forwarded.
    pub fn forwarded_by(mut self, relay_node: u8) -> Option<Self> {
        self.hop_limit = self.hop_limit.checked_sub(1)?;
        self.relay_node = relay_node;
        Some(self)
    }

    /// Build the 128-bit AES-CTR initial counter from packet ID and source.
    ///
    /// Each 32-bit header value is widened to a little-endian 64-bit word. The
    /// resulting 16 bytes are interpreted as a big-endian counter by AES-CTR.
    pub fn nonce(self) -> [u8; 16] {
        let mut nonce = [0; 16];
        nonce[0..8].copy_from_slice(&u64::from(self.packet_id).to_le_bytes());
        nonce[8..16].copy_from_slice(&u64::from(self.source).to_le_bytes());
        nonce
    }
}

/// One complete LoRa transport packet. `payload` is uninterpreted at this layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        let header = Header::decode(bytes)?;
        let payload = &bytes[HEADER_LEN..];
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(TransportError::PayloadTooLong(payload.len()));
        }
        Ok(Self {
            header,
            payload: payload.to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(TransportError::PayloadTooLong(self.payload.len()));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header.encode()?);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Encrypt or decrypt the payload in place with channel AES-CTR.
    ///
    /// CTR is symmetric, so applying this twice with the same key and header
    /// restores the original bytes.
    pub fn apply_channel_cipher(&mut self, key: &ChannelKey) {
        apply_channel_cipher(key, self.header.nonce(), &mut self.payload);
    }
}

fn apply_channel_cipher(key: &ChannelKey, nonce: [u8; 16], payload: &mut [u8]) {
    match key {
        ChannelKey::Aes128(key) => {
            let mut cipher = Aes128Ctr::new(key.into(), (&nonce).into());
            cipher.apply_keystream(payload);
        }
        ChannelKey::Aes256(key) => {
            let mut cipher = Aes256Ctr::new(key.into(), (&nonce).into());
            cipher.apply_keystream(payload);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    TruncatedHeader { actual: usize },
    PayloadTooLong(usize),
    HopLimit(u8),
    HopStart(u8),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => {
                write!(f, "radio header needs {HEADER_LEN} bytes, got {actual}")
            }
            Self::PayloadTooLong(actual) => {
                write!(f, "radio payload exceeds {MAX_PAYLOAD_LEN} bytes: {actual}")
            }
            Self::HopLimit(value) => write!(f, "hop limit does not fit three bits: {value}"),
            Self::HopStart(value) => write!(f, "hop start does not fit three bits: {value}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_example_header() -> Header {
        Header {
            destination: BROADCAST_DESTINATION,
            source: 0x06ca_ff30,
            packet_id: 0x2a72_101e,
            hop_limit: 3,
            want_ack: false,
            via_mqtt: false,
            hop_start: 3,
            channel_hash: 188,
            next_hop: 0,
            relay_node: 0,
        }
    }

    #[test]
    fn header_matches_published_byte_layout() {
        let bytes = published_example_header().encode().unwrap();
        assert_eq!(
            bytes,
            [
                0xff, 0xff, 0xff, 0xff, 0x30, 0xff, 0xca, 0x06, 0x1e, 0x10, 0x72, 0x2a, 0x63, 0xbc,
                0x00, 0x00,
            ]
        );
        assert_eq!(Header::decode(&bytes).unwrap(), published_example_header());
    }

    #[test]
    fn nonce_matches_published_two_little_endian_words() {
        assert_eq!(
            published_example_header().nonce(),
            [
                0x1e, 0x10, 0x72, 0x2a, 0, 0, 0, 0, 0x30, 0xff, 0xca, 0x06, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn channel_cipher_round_trips_opaque_payload() {
        let original = b"\x08\x01\x12\x0eThis is a test".to_vec();
        let mut packet = Packet {
            header: published_example_header(),
            payload: original.clone(),
        };
        let key = ChannelKey::Aes256([0x5a; 32]);
        packet.apply_channel_cipher(&key);
        assert_ne!(packet.payload, original);
        packet.apply_channel_cipher(&key);
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn channel_cipher_matches_independent_published_example() {
        let mut packet = Packet {
            header: published_example_header(),
            payload: b"\x08\x01\x12\x0eThis is a test".to_vec(),
        };
        let key = ChannelKey::Aes256([
            0x77, 0xd3, 0xf7, 0x72, 0xc7, 0xba, 0xcf, 0x97, 0xb4, 0xdf, 0x0f, 0x74, 0xc8, 0x32,
            0xa0, 0x0d, 0x00, 0xa8, 0xbb, 0xf0, 0x0d, 0xc0, 0xd3, 0x32, 0xd8, 0x99, 0xbd, 0x0f,
            0x85, 0x0b, 0x1f, 0x99,
        ]);
        packet.apply_channel_cipher(&key);
        assert_eq!(
            packet.payload,
            [
                0x56, 0xf4, 0xd1, 0xf7, 0xdd, 0xe8, 0x0f, 0xa6, 0x28, 0xb3, 0x66, 0xce, 0x42, 0x33,
                0x26, 0xad, 0xfc, 0xed,
            ]
        );
    }

    #[test]
    fn packet_round_trips_without_interpreting_payload() {
        let packet = Packet {
            header: published_example_header(),
            payload: vec![0x00, 0x80, 0xff],
        };
        assert_eq!(Packet::decode(&packet.encode().unwrap()).unwrap(), packet);
    }

    #[test]
    fn forwarding_preserves_cipher_identity() {
        let header = published_example_header();
        let forwarded = header.forwarded_by(0x30).unwrap();
        assert_eq!(forwarded.hop_limit, 2);
        assert_eq!(forwarded.relay_node, 0x30);
        assert_eq!(forwarded.source, header.source);
        assert_eq!(forwarded.packet_id, header.packet_id);
        assert_eq!(forwarded.nonce(), header.nonce());
    }

    #[test]
    fn zero_hop_packet_is_not_forwarded() {
        let mut header = published_example_header();
        header.hop_limit = 0;
        assert_eq!(header.forwarded_by(0x30), None);
    }

    #[test]
    fn bounds_are_checked() {
        assert!(matches!(
            Header::decode(&[0; 15]),
            Err(TransportError::TruncatedHeader { actual: 15 })
        ));
        let mut header = published_example_header();
        header.hop_limit = 8;
        assert_eq!(header.encode(), Err(TransportError::HopLimit(8)));
        let packet = Packet {
            header: published_example_header(),
            payload: vec![0; 238],
        };
        assert_eq!(packet.encode(), Err(TransportError::PayloadTooLong(238)));
    }
}
