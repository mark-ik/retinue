//! Path requests and responses.
//!
//! When an endpoint wants to reach a destination it has not heard announce, it asks: it
//! sends a path request to the well-known plain destination `rnstransport.path.request`, and
//! whoever owns the destination (or a transport node holding its announce) replies with a
//! *path response*: an ordinary announce whose context byte is [`CTX_PATH_RESPONSE`] rather
//! than `0`. retinue *sends* path requests, *ingests* the announces that result, and
//! *answers* path requests for destinations it owns (see [`parse_request`] and the endpoint's
//! path-response handling). It does not yet answer on behalf of others (no announce cache).
//!
//! The request is a plain data packet:
//!
//! ```text
//! destination = trunc16(SHA256(name_hash("rnstransport.path.request")))  = the plain dest
//! payload     = target_hash(16) || request_tag(16)
//! ```
//!
//! The response is a normal announce with the context byte set to [`CTX_PATH_RESPONSE`].
//!
//! Captured from RNS 1.3.8 (oracle/capture_pathreq.py, capture_pathresp.py):
//! `RNS.Transport.request_path` emits the request above to destination
//! `6b9f66014d9853faab220fba47d02761`; answering a path request for its own destination, RNS
//! emits a 167-byte announce with context byte `0x0b`.

use crate::destination::DestinationName;
use crate::hash::AddressHash;
use crate::packet::{DestinationType, HeaderType, Packet, PacketType, Propagation};

/// Length of the random request tag on a path request.
pub const TAG_LEN: usize = 16;

/// Context byte marking an announce as a solicited path response rather than a spontaneous
/// broadcast. Verified against RNS 1.3.8: answering a path request for its own destination,
/// RNS emits a normal announce carrying this context byte.
pub const CTX_PATH_RESPONSE: u8 = 0x0b;

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

/// Parse an incoming path request, returning the destination hash being sought.
///
/// Returns `None` unless `packet` is a plain data packet addressed to
/// [`path_request_destination`] carrying at least a 16-byte target hash. The trailing request
/// tag is the requester's private correlation value and is not needed to answer, so it is
/// ignored here.
pub fn parse_request(packet: &Packet) -> Option<AddressHash> {
    if packet.packet_type != PacketType::Data
        || packet.destination_type != DestinationType::Plain
        || packet.destination != path_request_destination()
    {
        return None;
    }
    AddressHash::from_slice(&packet.payload)
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

    #[test]
    fn parse_request_recovers_the_target() {
        let target = AddressHash::from_bytes([0x5A; 16]);
        let tag = [0x11; TAG_LEN];
        let req = path_request(target, &tag);
        // Survives an encode/decode round trip, as it would arriving off the wire.
        let round = Packet::decode(&req.encode()).unwrap();
        assert_eq!(parse_request(&round), Some(target));
    }

    #[test]
    fn parse_request_rejects_non_requests() {
        // Right shape, wrong destination.
        let mut wrong_dest = path_request(AddressHash::from_bytes([1; 16]), &[0; TAG_LEN]);
        wrong_dest.destination = AddressHash::from_bytes([0xFF; 16]);
        assert_eq!(parse_request(&wrong_dest), None);

        // Right destination, but an announce, not a data packet.
        let mut wrong_type = path_request(AddressHash::from_bytes([1; 16]), &[0; TAG_LEN]);
        wrong_type.packet_type = PacketType::Announce;
        assert_eq!(parse_request(&wrong_type), None);

        // Addressed correctly but truncated below a full target hash.
        let mut short = path_request(AddressHash::from_bytes([1; 16]), &[0; TAG_LEN]);
        short.payload.truncate(8);
        assert_eq!(parse_request(&short), None);
    }
}
