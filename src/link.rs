//! Link primitives: the mode/MTU trailer, and the link id.
//!
//! This is not yet a link implementation (that is R3). It is the two facts that a link
//! implementation cannot be written without, both of which were settled by capturing a
//! real handshake, because a wrong guess on either means no link ever completes and there
//! is no useful error to debug.
//!
//! # The trailer
//!
//! An RNS 1.x link request carries **67** bytes, not 64: the two ephemeral public keys and
//! then a 3-byte trailer. A link proof carries **99**, not 96: signature, public key, and
//! the same trailer. The trailer is a 24-bit big-endian field:
//!
//! ```text
//! bits 23..21  the AES mode   (0 = AES-128-CBC, 1 = AES-256-CBC)
//! bits 20..0   the MTU
//! ```
//!
//! Observed: an initiator sends `20 20 00` = mode 1, MTU 8192. The responder answers
//! `20 01 f4` = mode 1, MTU 500, which is exactly `Reticulum.MTU`. So this is an MTU
//! negotiation, and the mode is AES-256 on both sides.
//!
//! Beechat sends a bare 64-byte request and does not participate in any of this.
//!
//! # The link id
//!
//! The link id is a truncated hash over the link request, and the details are unobvious:
//!
//! ```text
//! link_id = trunc16(SHA256( (flags & 0x0F) || destination(16) || context(1) || payload[..64] ))
//! ```
//!
//! Two things to note. `hops` is excluded, which makes sense: it mutates in transit. And
//! the payload is **truncated to the 64 bytes of keys**, so the trailer deliberately does
//! not affect the link id, which is also sensible because the trailer is negotiable.
//!
//! Derived by solving against two independently captured (request, link id) pairs; only
//! this formula satisfies both. See `oracle/capture_link.py`.

use crate::hash::AddressHash;
use crate::packet::Packet;
use crate::{Error, Result};

/// Length of the mode/MTU trailer on link requests and proofs.
pub const TRAILER_LEN: usize = 3;

/// Bytes of key material in a link request: two 32-byte public keys.
pub const LINK_KEYS_LEN: usize = 64;

/// Bytes of a link request: the keys plus the trailer.
pub const LINK_REQUEST_LEN: usize = LINK_KEYS_LEN + TRAILER_LEN;

/// Bytes of a link proof: signature (64), public key (32), and the trailer.
pub const LINK_PROOF_LEN: usize = 64 + 32 + TRAILER_LEN;

/// The symmetric cipher a link will use. Negotiated, not fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMode {
    Aes128Cbc,
    Aes256Cbc,
}

impl LinkMode {
    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(Self::Aes128Cbc),
            1 => Ok(Self::Aes256Cbc),
            _ => Err(Error::BadLinkMode),
        }
    }

    fn to_bits(self) -> u32 {
        match self {
            Self::Aes128Cbc => 0,
            Self::Aes256Cbc => 1,
        }
    }
}

/// The 3-byte trailer on a link request or proof: a cipher mode and an MTU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkTrailer {
    pub mode: LinkMode,
    pub mtu: u32,
}

/// The largest MTU the 21-bit field can carry.
pub const MAX_MTU: u32 = (1 << 21) - 1;

impl LinkTrailer {
    /// Decode the trailer. `mode` occupies the top 3 bits, `mtu` the low 21.
    pub fn decode(bytes: &[u8; TRAILER_LEN]) -> Result<Self> {
        let raw = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        Ok(Self {
            mode: LinkMode::from_bits((raw >> 21) as u8)?,
            mtu: raw & MAX_MTU,
        })
    }

    /// Encode the trailer.
    pub fn encode(&self) -> [u8; TRAILER_LEN] {
        let raw = (self.mode.to_bits() << 21) | (self.mtu & MAX_MTU);
        [(raw >> 16) as u8, (raw >> 8) as u8, raw as u8]
    }
}

/// The link id implied by a link-request packet.
///
/// Returns [`Error::Truncated`] if the payload is too short to hold the key material.
pub fn link_id(request: &Packet) -> Result<AddressHash> {
    if request.payload.len() < LINK_KEYS_LEN {
        return Err(Error::Truncated);
    }

    let mut buf = Vec::with_capacity(1 + 16 + 1 + LINK_KEYS_LEN);
    // The flag byte is masked: the high nibble carries bits that change in transit (ifac,
    // header type, context flag, propagation), so they cannot be part of a stable id.
    //
    // Caveat, stated because it matters: both captured samples had flags == 0x02, where
    // masking is a no-op, so the capture does NOT prove the mask. It is taken on the
    // manual's and Beechat's authority, and only becomes observable for a link request
    // that arrives over a transport hop. Revisit if a two-hop link ever fails.
    buf.push(request.encode()[0] & 0x0F);
    buf.extend_from_slice(request.destination.as_slice());
    buf.push(request.context);
    buf.extend_from_slice(&request.payload[..LINK_KEYS_LEN]);

    Ok(AddressHash::of(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{DestinationType, HeaderType, PacketType, Propagation};

    fn request(dest_hex: &str, payload_hex: &str) -> Packet {
        let mut dest = [0u8; 16];
        hex::decode_to_slice(dest_hex, &mut dest).unwrap();
        Packet {
            ifac: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            propagation: Propagation::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
            hops: 0,
            transport: None,
            destination: AddressHash::from_bytes(dest),
            context: 0,
            payload: hex::decode(payload_hex).unwrap(),
        }
    }

    /// Captured: RNS proved back to this link id for a 64-byte request retinue sent it.
    #[test]
    fn link_id_matches_the_captured_proof_address() {
        let p = request(
            "a8725a7e212dace39e9f99a8ac5da28c",
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20\
             a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
        );
        assert_eq!(
            link_id(&p).unwrap().to_string(),
            "7c88505173382e78aaaae5ecdf122eec",
        );
    }

    /// Captured: RNS reported this link id for the 67-byte request it sent retinue. The
    /// trailer must NOT feed the hash, and this is the case that proves it.
    #[test]
    fn link_id_ignores_the_trailer() {
        let p = request(
            "19208507854a8a0b871f881170d475aa",
            "f72075eeade493f3a3fd94d98cba8b628cf5cce2532b0903b48b1c2024676164\
             f7cf9beb5793e668eb8c589096d382c616db7a7ebdd0ec6407e8a7d89452dd4e\
             202000",
        );
        assert_eq!(p.payload.len(), LINK_REQUEST_LEN);
        assert_eq!(
            link_id(&p).unwrap().to_string(),
            "5452ae4c3251cffa6b080779f943dfa4",
        );
    }

    #[test]
    fn captured_trailers_decode() {
        // What an RNS initiator sends: AES-256, asking for 8192.
        let req = LinkTrailer::decode(&[0x20, 0x20, 0x00]).unwrap();
        assert_eq!(req.mode, LinkMode::Aes256Cbc);
        assert_eq!(req.mtu, 8192);

        // What the responder answers: AES-256, settling on 500 (= Reticulum.MTU).
        let proof = LinkTrailer::decode(&[0x20, 0x01, 0xf4]).unwrap();
        assert_eq!(proof.mode, LinkMode::Aes256Cbc);
        assert_eq!(proof.mtu, 500);
    }

    #[test]
    fn trailers_round_trip() {
        for t in [
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 8192 },
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
            LinkTrailer { mode: LinkMode::Aes128Cbc, mtu: 500 },
        ] {
            assert_eq!(LinkTrailer::decode(&t.encode()).unwrap(), t);
        }
        assert_eq!(
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 8192 }.encode(),
            [0x20, 0x20, 0x00],
        );
    }

    #[test]
    fn a_short_payload_is_an_error() {
        let p = request("a8725a7e212dace39e9f99a8ac5da28c", "0faa");
        assert!(link_id(&p).is_err());
    }
}
