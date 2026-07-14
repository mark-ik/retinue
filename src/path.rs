//! Path requests.
//!
//! When an endpoint wants to reach a destination it has not heard announce, it asks: it
//! sends a path request to the well-known plain destination `rnstransport.path.request`, and
//! a transport node that knows a path replies by having the destination announce back toward
//! the requester. retinue is an endpoint, not a router, so it *sends* path requests and
//! *ingests* the announces that result; it never answers them.
//!
//! The packet is a plain data packet:
//!
//! ```text
//! destination = trunc16(SHA256(name_hash("rnstransport.path.request")))  = the plain dest
//! payload     = target_hash(16) || request_tag(16)
//! ```
//!
//! Captured from RNS 1.3.8: `RNS.Transport.request_path` emits exactly this, to destination
//! `6b9f66014d9853faab220fba47d02761`.

use crate::destination::DestinationName;
use crate::hash::AddressHash;
use crate::packet::{DestinationType, HeaderType, Packet, PacketType, Propagation};

/// Length of the random request tag on a path request.
pub const TAG_LEN: usize = 16;

/// The well-known destination hash a path request is addressed to.
pub fn path_request_destination() -> AddressHash {
    DestinationName::new("rnstransport", ["path", "request"]).plain_hash()
}

/// Build a path request for `target`.
///
/// `tag` is a random 16-byte value the caller supplies, so this stays RNG-free and
/// reproducible; it must be fresh per request in production, where it lets a requester
/// recognise the response to its own query.
pub fn path_request(target: AddressHash, tag: &[u8; TAG_LEN]) -> Packet {
    let mut payload = Vec::with_capacity(crate::hash::ADDRESS_HASH_LEN + TAG_LEN);
    payload.extend_from_slice(target.as_slice());
    payload.extend_from_slice(tag);

    Packet {
        ifac: false,
        header_type: HeaderType::Type1,
        context_flag: false,
        propagation: Propagation::Broadcast,
        destination_type: DestinationType::Plain,
        packet_type: PacketType::Data,
        hops: 0,
        transport: None,
        destination: path_request_destination(),
        context: 0,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answer from capturing `RNS.Transport.request_path`.
    #[test]
    fn path_request_destination_matches_rns() {
        assert_eq!(
            path_request_destination().to_string(),
            "6b9f66014d9853faab220fba47d02761",
        );
    }

    #[test]
    fn path_request_layout() {
        let target = AddressHash::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let tag = [0xAB; TAG_LEN];
        let p = path_request(target, &tag);

        assert_eq!(p.packet_type, PacketType::Data);
        assert_eq!(p.destination_type, DestinationType::Plain);
        assert_eq!(p.destination, path_request_destination());
        assert_eq!(&p.payload[..16], target.as_slice());
        assert_eq!(&p.payload[16..], &tag);

        // Re-decoding a re-encoding preserves it.
        let round = Packet::decode(&p.encode()).unwrap();
        assert_eq!(round.payload, p.payload);
        assert_eq!(round.destination_type, DestinationType::Plain);
    }
}
