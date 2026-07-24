//! Packet dedup and the flood/direct forwarding decision.
//!
//! These are the routing mechanics beneath the message layer: a seen-packet ring that
//! suppresses flood duplicates, and the decision — per MeshCore's `routeRecvPacket` — of
//! whether and how a received packet is retransmitted. Both are V1 (1-byte path hashes).
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use crate::packet::{HASH_SIZE, MAX_PATH, Packet, ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD};

/// Capacity of the seen-packet ring (MeshCore `SimpleMeshTables`: 128 + 32).
pub const MAX_PACKET_HASHES: usize = 160;

/// A fixed-size ring of recently-seen packet hashes, for flood dedup.
///
/// Matches MeshCore's `hasSeen`: a linear-scan check-and-insert with ring eviction and no time
/// expiry (an entry ages out only after `MAX_PACKET_HASHES` further distinct packets).
pub struct SeenTable {
    hashes: [[u8; HASH_SIZE]; MAX_PACKET_HASHES],
    next: usize,
}

impl SeenTable {
    pub fn new() -> Self {
        SeenTable {
            hashes: [[0u8; HASH_SIZE]; MAX_PACKET_HASHES],
            next: 0,
        }
    }

    /// Returns `true` if this packet's hash was already recorded (a duplicate); otherwise
    /// records it and returns `false`.
    pub fn has_seen(&mut self, packet: &Packet) -> bool {
        let h = packet.packet_hash();
        if self.hashes.contains(&h) {
            return true;
        }
        self.hashes[self.next] = h;
        self.next = (self.next + 1) % MAX_PACKET_HASHES;
        false
    }
}

impl Default for SeenTable {
    fn default() -> Self {
        Self::new()
    }
}

/// The forwarding decision for a received packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Forward {
    /// Do not retransmit (consumed by us, not our hop, a leaf node, or zero-hop).
    Drop,
    /// Retransmit this path-mutated packet.
    Retransmit(Box<Packet>),
}

/// Decide whether and how to retransmit a received packet, per MeshCore `routeRecvPacket`.
///
/// - `self_hash`: this node's 1-byte hash.
/// - `allow_forward`: `false` on a leaf/companion node (never forwards), `true` on a repeater.
/// - `consumed`: `true` when the packet was addressed to and handled by this node, so it is
///   not re-flooded (MeshCore's `markDoNotRetransmit`).
///
/// Flood packets are retransmitted with this node's hash appended to the path (if it fits);
/// direct packets are retransmitted only by the next hop (the first path entry), which
/// consumes itself from the front of the path. Zero-hop direct packets are neighbour-only.
pub fn route_recv(packet: &Packet, self_hash: u8, allow_forward: bool, consumed: bool) -> Forward {
    if !allow_forward || consumed {
        return Forward::Drop;
    }
    let count = packet.path_hop_count();
    let size = packet.path_hop_size();

    match packet.route_type() {
        ROUTE_FLOOD | ROUTE_TRANSPORT_FLOOD => {
            // No room to append our hash if it would overflow the byte limit or the 6-bit hop
            // count. (Upstream checks only the byte limit, which lets count 63 -> 64 corrupt
            // the size bits; guarding the count field too avoids that boundary bug.)
            let new_count = count as usize + 1;
            if new_count > 63 || new_count * size as usize > MAX_PATH {
                return Forward::Drop;
            }
            let mut fwd = packet.clone();
            fwd.path.push(self_hash); // V1: one-byte hash
            fwd.path_len = ((size - 1) << 6) | (count + 1);
            Forward::Retransmit(Box::new(fwd))
        }
        _ => {
            // Direct (source-routed): only the next hop forwards.
            if count == 0 || packet.path.first().copied() != Some(self_hash) {
                return Forward::Drop;
            }
            let mut fwd = packet.clone();
            fwd.path.drain(..size as usize); // consume ourselves from the front
            fwd.path_len = ((size - 1) << 6) | (count - 1);
            Forward::Retransmit(Box::new(fwd))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ROUTE_DIRECT, payload_type};

    fn flood(payload: &[u8]) -> Packet {
        let mut p = Packet::new(ROUTE_FLOOD, payload_type::TXT_MSG);
        p.payload = payload.to_vec();
        p
    }

    #[test]
    fn seen_table_is_check_and_insert() {
        let mut t = SeenTable::new();
        let a = flood(b"alpha");
        let b = flood(b"beta");
        assert!(!t.has_seen(&a), "first sighting is new");
        assert!(t.has_seen(&a), "second is a duplicate");
        assert!(!t.has_seen(&b), "a different packet is independent");
        assert!(t.has_seen(&b));
    }

    #[test]
    fn seen_table_evicts_after_capacity() {
        let mut t = SeenTable::new();
        let first = flood(b"first");
        assert!(!t.has_seen(&first));
        // Push MAX_PACKET_HASHES distinct packets; the first entry is overwritten.
        for i in 0..MAX_PACKET_HASHES as u32 {
            t.has_seen(&flood(&i.to_le_bytes()));
        }
        assert!(!t.has_seen(&first), "the oldest entry has aged out");
    }

    #[test]
    fn a_leaf_never_forwards() {
        let p = flood(b"x");
        assert_eq!(route_recv(&p, 0x11, false, false), Forward::Drop);
    }

    #[test]
    fn a_consumed_packet_is_not_reflooded() {
        let p = flood(b"x");
        assert_eq!(route_recv(&p, 0x11, true, true), Forward::Drop);
    }

    #[test]
    fn flood_appends_our_hash_to_the_path() {
        let p = flood(b"broadcast");
        match route_recv(&p, 0x2A, true, false) {
            Forward::Retransmit(fwd) => {
                assert_eq!(fwd.path_hop_count(), 1);
                assert_eq!(fwd.path, vec![0x2A]);
            }
            other => panic!("expected retransmit, got {other:?}"),
        }
    }

    #[test]
    fn flood_drops_when_the_path_is_full() {
        // 63 hops at size 1 is the most the 6-bit count field encodes; a 64th would overflow
        // it, so a full path drops rather than corrupt the packet.
        let mut p = flood(b"full");
        p.path = vec![0u8; 63];
        p.path_len = 63; // size 1, count 63
        assert_eq!(route_recv(&p, 0x01, true, false), Forward::Drop);
    }

    #[test]
    fn direct_forwards_only_at_the_next_hop() {
        let mut p = Packet::new(ROUTE_DIRECT, payload_type::TXT_MSG);
        p.payload = b"routed".to_vec();
        p.path = vec![0x2A, 0x3B, 0x4C];
        p.path_len = 3; // size 1, count 3

        // We are the next hop (0x2A): forward with ourselves consumed from the front.
        match route_recv(&p, 0x2A, true, false) {
            Forward::Retransmit(fwd) => {
                assert_eq!(fwd.path, vec![0x3B, 0x4C]);
                assert_eq!(fwd.path_hop_count(), 2);
            }
            other => panic!("expected retransmit, got {other:?}"),
        }
        // We are not the next hop: drop.
        assert_eq!(route_recv(&p, 0x99, true, false), Forward::Drop);
    }

    #[test]
    fn direct_zero_hop_is_neighbour_only() {
        let mut p = Packet::new(ROUTE_DIRECT, payload_type::ACK);
        p.payload = b"ack".to_vec();
        assert_eq!(p.path_hop_count(), 0);
        assert_eq!(route_recv(&p, 0x2A, true, false), Forward::Drop);
    }
}
