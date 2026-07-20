//! A sans-io MeshCore node: the pipeline that ties identity, cipher, message, dedup, and
//! forwarding together.
//!
//! It holds no radio and no clock. A caller (a pump over a [`tulle`](https://github.com/mark-ik/tulle)
//! modem, or an in-process test) feeds received frames to [`Node::on_frame`] and transmits the
//! frames the node emits — retransmissions for flood/direct routing, plus whatever the app
//! composes with [`Node::advert_frame`], [`Node::text_frame`], and [`Node::ack_frame`].
//!
//! Receive pipeline: decode the packet, drop flood duplicates ([`crate::mesh::SeenTable`]),
//! dispatch by payload type (verify and learn adverts; decrypt text addressed to us and
//! surface its ack; note acks), then decide retransmission ([`crate::mesh::route_recv`]).
//!
//! Text messaging works only after the two ends have heard each other's adverts, since the
//! per-pair cipher key is ECDH over the peer's public key. Messages flood by default (no known
//! route required); a direct-routing optimization is a follow-on. This is V1 (1-byte hashes).
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use std::collections::HashMap;

use crate::advert::Advert;
use crate::identity::{Identity, LocalIdentity};
use crate::mesh::{Forward, SeenTable, route_recv};
use crate::message::{TextMessage, decode_ack, encode_ack};
use crate::packet::{Packet, ROUTE_FLOOD, payload_type};

/// Something the node surfaces to the application from a received frame.
#[derive(Debug, Clone)]
pub enum Event {
    /// A contact advertised itself (a new or refreshed identity).
    Advert {
        identity: Identity,
        timestamp: u32,
        app_data: Vec<u8>,
    },
    /// A text message addressed to us, decrypted, with the ack we should return.
    Message {
        /// The sender's 1-byte node hash.
        from: u8,
        message: TextMessage,
        ack: [u8; 4],
    },
    /// An ack floated past (whoever is awaiting it matches the 4 bytes).
    Ack([u8; 4]),
}

/// A MeshCore node.
pub struct Node {
    identity: LocalIdentity,
    me: Identity,
    seen: SeenTable,
    allow_forward: bool,
    /// Learned contacts, keyed by 1-byte node hash. A collision (two peers sharing a hash byte)
    /// keeps the most recently advertised, matching the wire's 1-byte addressing.
    contacts: HashMap<u8, Identity>,
}

impl Node {
    /// A node with the given identity. `allow_forward` is `true` for a repeater (retransmits
    /// others' traffic), `false` for a leaf.
    pub fn new(identity: LocalIdentity, allow_forward: bool) -> Self {
        let me = identity.identity();
        Node {
            identity,
            me,
            seen: SeenTable::new(),
            allow_forward,
            contacts: HashMap::new(),
        }
    }

    /// Our identity.
    pub fn identity(&self) -> &Identity {
        &self.me
    }

    /// Our 1-byte node hash.
    pub fn my_hash(&self) -> u8 {
        self.me.hash()[0]
    }

    /// A learned contact by node hash.
    pub fn contact(&self, hash: u8) -> Option<&Identity> {
        self.contacts.get(&hash)
    }

    /// Handle one received raw frame. Returns `(events for the app, frames to retransmit)`.
    pub fn on_frame(&mut self, frame: &[u8]) -> (Vec<Event>, Vec<Vec<u8>>) {
        let mut events = Vec::new();
        let mut out = Vec::new();

        let Some(packet) = Packet::decode(frame) else {
            return (events, out);
        };
        // Flood dedup: a packet we have already handled is neither re-surfaced nor re-forwarded.
        if self.seen.has_seen(&packet) {
            return (events, out);
        }

        let consumed = self.dispatch(&packet, &mut events);

        if let Forward::Retransmit(fwd) = route_recv(&packet, self.my_hash(), self.allow_forward, consumed) {
            out.push(fwd.encode());
        }
        (events, out)
    }

    /// Process a packet by payload type, pushing any events. Returns whether it was consumed by
    /// this node (addressed to us and handled), which suppresses re-forwarding.
    fn dispatch(&mut self, packet: &Packet, events: &mut Vec<Event>) -> bool {
        match packet.payload_type() {
            payload_type::ADVERT => {
                if let Some(adv) = Advert::decode(&packet.payload) {
                    self.contacts
                        .insert(adv.identity.hash()[0], adv.identity.clone());
                    events.push(Event::Advert {
                        identity: adv.identity,
                        timestamp: adv.timestamp,
                        app_data: adv.app_data,
                    });
                }
                false // adverts flood onward
            }
            payload_type::TXT_MSG => {
                // Addressed to us? payload = dest_hash(1) || src_hash(1) || blob.
                if packet.payload.first() != Some(&self.my_hash()) {
                    return false; // not ours: forward it
                }
                let Some(&src_hash) = packet.payload.get(1) else {
                    return false;
                };
                let Some(sender) = self.contacts.get(&src_hash).cloned() else {
                    // We do not know the sender yet, so we cannot derive the key. Let it forward
                    // in case another node can (and we may learn the sender's advert later).
                    return false;
                };
                let Some(secret) = self.identity.shared_secret(&sender) else {
                    return false;
                };
                match TextMessage::decode(&packet.payload, &secret) {
                    Some((_, _, message)) => {
                        let ack = message.ack_crc(&sender.pub_key);
                        events.push(Event::Message {
                            from: src_hash,
                            message,
                            ack,
                        });
                        true // ours, handled
                    }
                    None => false,
                }
            }
            payload_type::ACK => {
                if let Some(ack) = decode_ack(&packet.payload) {
                    events.push(Event::Ack(ack));
                }
                false // acks flood to whoever awaits them
            }
            _ => false,
        }
    }

    /// Record a packet we are about to transmit as seen, so its echo off the air is suppressed.
    fn seal_outgoing(&mut self, packet: &Packet) -> Vec<u8> {
        self.seen.has_seen(packet);
        packet.encode()
    }

    /// A flood advert frame carrying our identity and `app_data`, to broadcast.
    pub fn advert_frame(&mut self, timestamp: u32, app_data: &[u8]) -> Vec<u8> {
        let payload = Advert::encode(&self.identity, timestamp, app_data)
            .expect("advert app_data within limit");
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::ADVERT);
        packet.payload = payload;
        self.seal_outgoing(&packet)
    }

    /// A flood text-message frame to a known contact `to`. `None` if `to` is unknown (we need
    /// its public key to derive the cipher key). Returns the frame and the ack to await.
    pub fn text_frame(&mut self, to: u8, timestamp: u32, text: &str) -> Option<(Vec<u8>, [u8; 4])> {
        let peer = self.contacts.get(&to).cloned()?;
        let secret = self.identity.shared_secret(&peer)?;
        let message = TextMessage::plain(timestamp, text);
        let expected_ack = message.ack_crc(&self.me.pub_key);
        let payload = message.encode(&secret, to, self.my_hash());
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::TXT_MSG);
        packet.payload = payload;
        Some((self.seal_outgoing(&packet), expected_ack))
    }

    /// A flood ACK frame carrying `ack`.
    pub fn ack_frame(&mut self, ack: [u8; 4]) -> Vec<u8> {
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::ACK);
        packet.payload = encode_ack(ack);
        self.seal_outgoing(&packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(seed: u8, forward: bool) -> Node {
        Node::new(LocalIdentity::from_seed([seed; 32]), forward)
    }

    #[test]
    fn two_nodes_advert_then_message_and_ack() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        assert_ne!(alice.my_hash(), bob.my_hash(), "seeds must not collide on the 1-byte hash");

        // Adverts both ways: each learns the other.
        let a_adv = alice.advert_frame(100, b"alice");
        let (ev, _) = bob.on_frame(&a_adv);
        assert!(matches!(ev.as_slice(), [Event::Advert { .. }]));
        assert!(bob.contact(alice.my_hash()).is_some(), "bob learned alice");

        let b_adv = bob.advert_frame(101, b"bob");
        alice.on_frame(&b_adv);
        assert!(alice.contact(bob.my_hash()).is_some(), "alice learned bob");

        // Alice sends bob a text; bob decrypts it and derives the matching ack.
        let (txt, expected_ack) = alice.text_frame(bob.my_hash(), 200, "hello bob").unwrap();
        let (ev, _) = bob.on_frame(&txt);
        let (from, message, ack) = match ev.as_slice() {
            [Event::Message { from, message, ack }] => (*from, message.clone(), *ack),
            other => panic!("expected a message, got {other:?}"),
        };
        assert_eq!(from, alice.my_hash());
        assert_eq!(message.text, "hello bob");
        assert_eq!(ack, expected_ack, "sender and receiver agree on the ack");

        // Bob acks; alice sees the ack she was awaiting.
        let ack_frame = bob.ack_frame(ack);
        let (ev, _) = alice.on_frame(&ack_frame);
        assert!(
            matches!(ev.as_slice(), [Event::Ack(a)] if *a == expected_ack),
            "alice matched her pending ack",
        );
    }

    #[test]
    fn a_duplicate_flood_is_dropped() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        let adv = alice.advert_frame(1, b"a");
        let (first, _) = bob.on_frame(&adv);
        assert_eq!(first.len(), 1, "first sighting surfaces an advert");
        let (second, _) = bob.on_frame(&adv);
        assert!(second.is_empty(), "the duplicate is suppressed");
    }

    #[test]
    fn a_repeater_forwards_a_flood_it_is_not_the_target_of() {
        let mut alice = node(0x11, false);
        let mut repeater = node(0x33, true); // allow_forward
        let adv = alice.advert_frame(1, b"a");
        let (events, out) = repeater.on_frame(&adv);
        assert!(matches!(events.as_slice(), [Event::Advert { .. }]));
        assert_eq!(out.len(), 1, "the repeater re-floods the advert");
        // The re-flooded packet carries the repeater's hash appended to the path.
        let fwd = Packet::decode(&out[0]).unwrap();
        assert_eq!(fwd.path, vec![repeater.my_hash()]);
    }

    #[test]
    fn a_leaf_does_not_forward() {
        let mut alice = node(0x11, false);
        let mut leaf = node(0x33, false); // no forwarding
        let adv = alice.advert_frame(1, b"a");
        let (_, out) = leaf.on_frame(&adv);
        assert!(out.is_empty(), "a leaf consumes without re-flooding");
    }

    #[test]
    fn a_message_for_someone_else_is_not_decrypted() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        let mut carol = node(0x44, true); // a forwarding bystander
        alice.on_frame(&bob.advert_frame(1, b"b"));
        bob.on_frame(&alice.advert_frame(2, b"a"));
        carol.on_frame(&alice.advert_frame(3, b"a"));

        let (txt, _) = alice.text_frame(bob.my_hash(), 5, "for bob only").unwrap();
        // Carol is not the target: no Message event, but she forwards it.
        let (events, out) = carol.on_frame(&txt);
        assert!(!events.iter().any(|e| matches!(e, Event::Message { .. })));
        assert_eq!(out.len(), 1, "carol forwards a message not addressed to her");
    }
}
