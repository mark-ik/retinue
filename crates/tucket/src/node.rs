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
//! per-pair cipher key is ECDH over the peer's public key. A first message floods when no route
//! is known; its authenticated PATH response establishes reciprocal direct routes for later
//! messages. This is V1 (1-byte path hashes).
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use std::collections::HashMap;

use crate::advert::{Advert, AdvertData};
use crate::identity::{Identity, LocalIdentity};
use crate::mesh::{Forward, SeenTable, route_recv};
use crate::message::{TextMessage, decode_ack, encode_ack};
use crate::packet::{Packet, ROUTE_DIRECT, ROUTE_FLOOD, payload_type};
use crate::path::PathMessage;

/// A validated source route to one contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectRoute {
    path_len: u8,
    path: Vec<u8>,
}

/// Retry behavior for one private text send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextRetryPolicy {
    /// Total transmissions including the initial attempt, from 1 through 4.
    pub attempts: u8,
    /// Clear a learned path and flood the last attempt.
    pub flood_last: bool,
}

impl TextRetryPolicy {
    pub fn new(attempts: u8, flood_last: bool) -> Option<Self> {
        (1..=4).contains(&attempts).then_some(Self {
            attempts,
            flood_last,
        })
    }
}

impl Default for TextRetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 4,
            flood_last: true,
        }
    }
}

/// Caller-driven state for one text awaiting an acknowledgement.
///
/// Tucket owns attempt numbering, route fallback, and matching delayed ACKs.
/// The caller owns the clock and decides when to ask for the next attempt.
#[derive(Clone, Debug)]
pub struct PendingText {
    to: u8,
    timestamp: u32,
    text: String,
    policy: TextRetryPolicy,
    next_attempt: u8,
    expected_acks: Vec<[u8; 4]>,
    complete: bool,
}

impl PendingText {
    pub fn attempts_sent(&self) -> u8 {
        self.next_attempt
    }

    pub fn attempts_remaining(&self) -> u8 {
        self.policy.attempts.saturating_sub(self.next_attempt)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Accept an ACK from any attempt already emitted. Delayed delivery of an
    /// earlier ACK still completes the send.
    pub fn acknowledge(&mut self, ack: [u8; 4]) -> bool {
        if self.expected_acks.contains(&ack) {
            self.complete = true;
            true
        } else {
            false
        }
    }
}

/// One concrete transmission produced from a [`PendingText`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextAttempt {
    pub frame: Vec<u8>,
    pub ack: [u8; 4],
    pub attempt: u8,
    pub flooded: bool,
}

impl DirectRoute {
    /// Construct a validated source route.
    ///
    /// `path_len` packs the hash width and hop count; `path` must contain exactly
    /// that many bytes. A zero-hop route is valid and addresses a radio neighbour
    /// directly.
    pub fn new(path_len: u8, path: &[u8]) -> Option<Self> {
        if !Packet::is_valid_path_len(path_len) {
            return None;
        }
        let byte_len = ((path_len >> 6) as usize + 1) * (path_len & 63) as usize;
        (path.len() == byte_len).then(|| Self {
            path_len,
            path: path.to_vec(),
        })
    }

    pub fn path_len(&self) -> u8 {
        self.path_len
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }
}

struct Contact {
    identity: Identity,
    route: Option<DirectRoute>,
}

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
    contacts: HashMap<u8, Contact>,
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
        self.contacts.get(&hash).map(|contact| &contact.identity)
    }

    /// The authenticated direct route currently learned for a contact.
    pub fn route_to(&self, hash: u8) -> Option<&DirectRoute> {
        self.contacts.get(&hash)?.route.as_ref()
    }

    /// Set an operator-selected route for a known contact.
    ///
    /// This is useful when topology policy or an independently measured path
    /// should take precedence over automatic flood discovery.
    pub fn set_route(&mut self, hash: u8, route: DirectRoute) -> bool {
        let Some(contact) = self.contacts.get_mut(&hash) else {
            return false;
        };
        contact.route = Some(route);
        true
    }

    /// Forget a route after a failed direct delivery so the next send floods and discovers a
    /// fresh one.
    pub fn clear_route(&mut self, hash: u8) {
        if let Some(contact) = self.contacts.get_mut(&hash) {
            contact.route = None;
        }
    }

    /// Begin a caller-timed private text send. Returns `None` until the peer's
    /// advert has supplied its public key.
    pub fn begin_text(
        &self,
        to: u8,
        timestamp: u32,
        text: impl Into<String>,
        policy: TextRetryPolicy,
    ) -> Option<PendingText> {
        self.contacts.get(&to)?;
        Some(PendingText {
            to,
            timestamp,
            text: text.into(),
            policy,
            next_attempt: 0,
            expected_acks: Vec::with_capacity(policy.attempts as usize),
            complete: false,
        })
    }

    /// Produce the next numbered attempt. Returns `None` after completion or
    /// when the configured attempt count is exhausted.
    pub fn next_text_attempt(&mut self, pending: &mut PendingText) -> Option<TextAttempt> {
        if pending.complete || pending.next_attempt >= pending.policy.attempts {
            return None;
        }
        let peer = self.contacts.get(&pending.to)?.identity.clone();
        let secret = self.identity.shared_secret(&peer)?;
        let attempt = pending.next_attempt;
        let flood_last = pending.policy.flood_last
            && attempt + 1 == pending.policy.attempts
            && self.route_to(pending.to).is_some();
        if flood_last {
            self.clear_route(pending.to);
        }

        let mut message = TextMessage::plain(pending.timestamp, pending.text.clone());
        message.attempt = attempt;
        let ack = message.ack_crc(&self.me.pub_key);
        let payload = message.encode(&secret, pending.to, self.my_hash());
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::TXT_MSG);
        packet.payload = payload;
        let frame = self.route_outgoing(pending.to, packet);
        let flooded = Packet::decode(&frame).is_some_and(|packet| packet.is_flood());

        pending.next_attempt += 1;
        pending.expected_acks.push(ack);
        Some(TextAttempt {
            frame,
            ack,
            attempt,
            flooded,
        })
    }

    /// Handle one received raw frame. Returns `(events for the app, frames to retransmit)`.
    pub fn on_frame(&mut self, frame: &[u8]) -> (Vec<Event>, Vec<Vec<u8>>) {
        let mut events = Vec::new();
        let mut out = Vec::new();

        let Some(packet) = Packet::decode(frame) else {
            return (events, out);
        };
        // A direct packet is processed only by its current next hop. Other radios hear the
        // same transmission but must not mark it seen before it reaches their turn in the
        // source route.
        let is_our_direct_hop =
            packet.path_hop_count() == 0 || packet.path.first().copied() == Some(self.my_hash());
        if !packet.is_flood() && !is_our_direct_hop {
            return (events, out);
        }
        if self.seen.has_seen(&packet) {
            return (events, out);
        }

        let consumed = self.dispatch(&packet, &mut events, &mut out);

        if let Forward::Retransmit(fwd) =
            route_recv(&packet, self.my_hash(), self.allow_forward, consumed)
        {
            out.push(fwd.encode());
        }
        (events, out)
    }

    /// Process a packet by payload type, pushing any events. Returns whether it was consumed by
    /// this node (addressed to us and handled), which suppresses re-forwarding.
    fn dispatch(
        &mut self,
        packet: &Packet,
        events: &mut Vec<Event>,
        out: &mut Vec<Vec<u8>>,
    ) -> bool {
        match packet.payload_type() {
            payload_type::ADVERT => {
                if let Some(adv) = Advert::decode(&packet.payload) {
                    let hash = adv.identity.hash()[0];
                    self.contacts
                        .entry(hash)
                        .and_modify(|contact| contact.identity = adv.identity.clone())
                        .or_insert(Contact {
                            identity: adv.identity.clone(),
                            route: None,
                        });
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
                let Some(sender) = self.contacts.get(&src_hash).map(|c| c.identity.clone()) else {
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
                        if packet.is_flood()
                            && let Some(frame) = self.path_frame(
                                src_hash,
                                packet.path_len,
                                &packet.path,
                                payload_type::ACK,
                                &ack,
                                None,
                            )
                        {
                            out.push(frame);
                        }
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
            payload_type::PATH => self.dispatch_path(packet, events, out),
            _ => false,
        }
    }

    fn dispatch_path(
        &mut self,
        packet: &Packet,
        events: &mut Vec<Event>,
        out: &mut Vec<Vec<u8>>,
    ) -> bool {
        if packet.payload.first() != Some(&self.my_hash()) {
            return false;
        }
        let Some(&src_hash) = packet.payload.get(1) else {
            return false;
        };
        let Some(sender) = self.contacts.get(&src_hash).map(|c| c.identity.clone()) else {
            return false;
        };
        let Some(secret) = self.identity.shared_secret(&sender) else {
            return false;
        };
        let Some((dest, src, path)) = PathMessage::decode(&packet.payload, &secret) else {
            return false;
        };
        if dest != self.my_hash() || src != src_hash {
            return false;
        }

        let route = DirectRoute {
            path_len: path.path_len,
            path: path.path.clone(),
        };
        if let Some(contact) = self.contacts.get_mut(&src_hash) {
            contact.route = Some(route.clone());
        }
        if path.extra_type == payload_type::ACK
            && let Some(ack) = decode_ack(&path.extra)
        {
            events.push(Event::Ack(ack));
        }

        if packet.is_flood()
            && let Some(frame) = self.path_frame(
                src_hash,
                packet.path_len,
                &packet.path,
                0,
                &[],
                Some(&route),
            )
        {
            out.push(frame);
        }
        true
    }

    fn path_frame(
        &mut self,
        to: u8,
        path_len: u8,
        path: &[u8],
        extra_type: u8,
        extra: &[u8],
        direct: Option<&DirectRoute>,
    ) -> Option<Vec<u8>> {
        let peer = self.contacts.get(&to)?.identity.clone();
        let secret = self.identity.shared_secret(&peer)?;
        let message = PathMessage::new(path_len, path, extra_type, extra)?;
        let payload = message.encode(&secret, to, self.my_hash())?;
        let mut packet = Packet::new(
            if direct.is_some() {
                ROUTE_DIRECT
            } else {
                ROUTE_FLOOD
            },
            payload_type::PATH,
        );
        packet.payload = payload;
        if let Some(route) = direct {
            packet.path_len = route.path_len;
            packet.path = route.path.clone();
        }
        Some(self.seal_outgoing(&packet))
    }

    fn route_outgoing(&mut self, to: u8, mut packet: Packet) -> Vec<u8> {
        if let Some(route) = self.contacts.get(&to).and_then(|c| c.route.clone()) {
            packet.header = (packet.header & !0x03) | ROUTE_DIRECT;
            packet.path_len = route.path_len;
            packet.path = route.path;
        }
        self.seal_outgoing(&packet)
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

    /// A flood advert using the current structured MeshCore application data.
    pub fn advert_frame_data(&mut self, timestamp: u32, data: &AdvertData) -> Option<Vec<u8>> {
        Some(self.advert_frame(timestamp, &data.encode()?))
    }

    /// A flood text-message frame to a known contact `to`. `None` if `to` is unknown (we need
    /// its public key to derive the cipher key). Returns the frame and the ack to await.
    pub fn text_frame(&mut self, to: u8, timestamp: u32, text: &str) -> Option<(Vec<u8>, [u8; 4])> {
        let mut pending = self.begin_text(to, timestamp, text, TextRetryPolicy::default())?;
        let attempt = self.next_text_attempt(&mut pending)?;
        Some((attempt.frame, attempt.ack))
    }

    /// A flood ACK frame carrying `ack`.
    pub fn ack_frame(&mut self, ack: [u8; 4]) -> Vec<u8> {
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::ACK);
        packet.payload = encode_ack(ack);
        self.seal_outgoing(&packet)
    }

    /// An ACK to a known contact, sent directly when a route is known and flooded otherwise.
    pub fn ack_frame_to(&mut self, to: u8, ack: [u8; 4]) -> Vec<u8> {
        let mut packet = Packet::new(ROUTE_FLOOD, payload_type::ACK);
        packet.payload = encode_ack(ack);
        self.route_outgoing(to, packet)
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
        assert_ne!(
            alice.my_hash(),
            bob.my_hash(),
            "seeds must not collide on the 1-byte hash"
        );

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
    fn operator_can_set_a_validated_route_for_a_known_contact() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        alice.on_frame(&bob.advert_frame(1, b"bob"));

        assert!(DirectRoute::new(2, &[0x33]).is_none());
        assert!(!alice.set_route(
            0xff,
            DirectRoute::new(1, &[0x33]).expect("valid one-hop route")
        ));
        assert!(alice.set_route(
            bob.my_hash(),
            DirectRoute::new(1, &[0x33]).expect("valid one-hop route")
        ));
        assert_eq!(
            alice.route_to(bob.my_hash()).expect("route stored").path(),
            &[0x33]
        );
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
        assert_eq!(
            out.len(),
            1,
            "carol forwards a message not addressed to her"
        );
    }

    #[test]
    fn flood_message_establishes_reciprocal_direct_routes() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        let mut repeater = node(0x33, true);

        // Each endpoint learns the other's identity through the repeater.
        let a_adv = alice.advert_frame(1, b"alice");
        let (_, forwarded) = repeater.on_frame(&a_adv);
        bob.on_frame(&forwarded[0]);
        let b_adv = bob.advert_frame(2, b"bob");
        let (_, forwarded) = repeater.on_frame(&b_adv);
        alice.on_frame(&forwarded[0]);

        // The first text floods. Bob's generated PATH response carries its ACK and Alice's
        // outbound route inside the pairwise cipher.
        let (first, expected_ack) = alice.text_frame(bob.my_hash(), 3, "find a path").unwrap();
        assert!(Packet::decode(&first).unwrap().is_flood());
        let (_, forwarded) = repeater.on_frame(&first);
        let (events, bob_out) = bob.on_frame(&forwarded[0]);
        assert!(matches!(events.as_slice(), [Event::Message { .. }]));
        assert_eq!(bob_out.len(), 1, "bob emits a PATH response");

        let (_, forwarded) = repeater.on_frame(&bob_out[0]);
        let (events, alice_out) = alice.on_frame(&forwarded[0]);
        assert!(matches!(events.as_slice(), [Event::Ack(ack)] if *ack == expected_ack));
        assert_eq!(
            alice.route_to(bob.my_hash()).unwrap().path(),
            &[repeater.my_hash()]
        );
        assert_eq!(
            alice_out.len(),
            1,
            "alice returns the reciprocal path directly"
        );

        let (_, forwarded) = repeater.on_frame(&alice_out[0]);
        bob.on_frame(&forwarded[0]);
        assert_eq!(
            bob.route_to(alice.my_hash()).unwrap().path(),
            &[repeater.my_hash()]
        );

        // Later text and its addressed ACK use the learned source routes in both directions.
        let (second, ack) = alice.text_frame(bob.my_hash(), 4, "now direct").unwrap();
        let second = Packet::decode(&second).unwrap();
        assert_eq!(second.route_type(), ROUTE_DIRECT);
        assert_eq!(second.path, vec![repeater.my_hash()]);
        let (_, forwarded) = repeater.on_frame(&second.encode());
        let (events, _) = bob.on_frame(&forwarded[0]);
        assert!(
            matches!(events.as_slice(), [Event::Message { message, .. }] if message.text == "now direct")
        );

        let ack_frame = bob.ack_frame_to(alice.my_hash(), ack);
        assert_eq!(
            Packet::decode(&ack_frame).unwrap().route_type(),
            ROUTE_DIRECT
        );
        let (_, forwarded) = repeater.on_frame(&ack_frame);
        let (events, _) = alice.on_frame(&forwarded[0]);
        assert!(matches!(events.as_slice(), [Event::Ack(got)] if *got == ack));
    }

    fn establish_route(alice: &mut Node, bob: &mut Node, repeater: &mut Node) {
        let a_adv = alice.advert_frame(1, b"alice");
        let (_, forwarded) = repeater.on_frame(&a_adv);
        bob.on_frame(&forwarded[0]);
        let b_adv = bob.advert_frame(2, b"bob");
        let (_, forwarded) = repeater.on_frame(&b_adv);
        alice.on_frame(&forwarded[0]);

        let (first, _) = alice.text_frame(bob.my_hash(), 3, "learn route").unwrap();
        let (_, forwarded) = repeater.on_frame(&first);
        let (_, bob_out) = bob.on_frame(&forwarded[0]);
        let (_, forwarded) = repeater.on_frame(&bob_out[0]);
        let (_, alice_out) = alice.on_frame(&forwarded[0]);
        let (_, forwarded) = repeater.on_frame(&alice_out[0]);
        bob.on_frame(&forwarded[0]);
    }

    #[test]
    fn direct_retries_clear_the_path_and_flood_the_last_attempt() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        let mut repeater = node(0x33, true);
        establish_route(&mut alice, &mut bob, &mut repeater);
        assert!(alice.route_to(bob.my_hash()).is_some());

        let mut pending = alice
            .begin_text(bob.my_hash(), 10, "retry me", TextRetryPolicy::default())
            .unwrap();
        let attempts: Vec<_> = (0..4)
            .map(|_| alice.next_text_attempt(&mut pending).unwrap())
            .collect();

        assert_eq!(
            attempts
                .iter()
                .map(|attempt| attempt.attempt)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert!(attempts[..3].iter().all(|attempt| !attempt.flooded));
        assert!(attempts[3].flooded);
        assert!(alice.route_to(bob.my_hash()).is_none());
        assert_eq!(pending.attempts_remaining(), 0);
        assert!(alice.next_text_attempt(&mut pending).is_none());
    }

    #[test]
    fn delayed_ack_from_any_attempt_completes_the_send() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        alice.on_frame(&bob.advert_frame(1, b"bob"));

        let mut pending = alice
            .begin_text(bob.my_hash(), 10, "eventually", TextRetryPolicy::default())
            .unwrap();
        let first = alice.next_text_attempt(&mut pending).unwrap();
        let second = alice.next_text_attempt(&mut pending).unwrap();
        assert_ne!(first.ack, second.ack, "attempt is covered by the ACK hash");
        assert!(pending.acknowledge(first.ack));
        assert!(pending.is_complete());
        assert!(alice.next_text_attempt(&mut pending).is_none());
    }

    #[test]
    fn flood_fallback_can_be_disabled() {
        let mut alice = node(0x11, false);
        let mut bob = node(0x22, false);
        let mut repeater = node(0x33, true);
        establish_route(&mut alice, &mut bob, &mut repeater);

        let policy = TextRetryPolicy::new(2, false).unwrap();
        let mut pending = alice
            .begin_text(bob.my_hash(), 10, "stay direct", policy)
            .unwrap();
        assert!(!alice.next_text_attempt(&mut pending).unwrap().flooded);
        assert!(!alice.next_text_attempt(&mut pending).unwrap().flooded);
        assert!(alice.route_to(bob.my_hash()).is_some());
    }
}
