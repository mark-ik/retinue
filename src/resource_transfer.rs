//! Driving a resource transfer over a [`Link`]: the sans-io sender/receiver pair that runs
//! the resource codec ([`crate::resource`]) over link packets.
//!
//! A *resource* is RNS's segmented transfer of a payload too large for one packet. The codec
//! and its two state machines ([`Outgoing`], [`Incoming`]) are pinned to RNS 1.3.8's wire in
//! `resource.rs`; this module is the driver that moves their packets across a link, the way
//! [`crate::reliable`] drives the `Channel`/`Buffer` codec.
//!
//! # Wire, by link context byte
//!
//! ```text
//! 0x02 RESOURCE_ADV   the advertisement (msgpack), sealed; (re)sent until the receiver responds
//! 0x03 RESOURCE_REQ   the receiver's request for parts / solicitation for more hashmap, sealed
//! 0x01 RESOURCE       one part: a raw slice of the sealed token, framed (not re-sealed)
//! 0x04 RESOURCE_HMU   a hashmap update for a resource with more parts than one advert carries
//! 0x05 RESOURCE_PRF   the receiver's proof of receipt, framed: resource_hash(32) || proof(32)
//! ```
//!
//! The payload is sealed into the token **once** (`link.seal(content)`), then split into
//! parts, so a part is a byte-slice of the already-encrypted token and rides framed; the
//! receiver reassembles the parts verbatim into the token and opens it once. Control packets
//! (advertisement, request, hashmap update) are sealed; the proof, carrying only public
//! hashes, is framed. This matches the codec's own round-trip usage (see `resource.rs` tests)
//! and the captured advertisement; per-context sealing for RNS interop of REQ/HMU is pinned
//! for ADV/PART/PRF and is a follow-on capture for the rest.
//!
//! Both halves are sans-io: [`ResourceSender::on_packet`] / [`ResourceReceiver::on_packet`]
//! take a received packet and return packets to send, and the retransmit helpers re-emit on a
//! stall. A caller (a link task, or a virtual-clock loss test) pumps them.

use crate::link::{
    CTX_RESOURCE, CTX_RESOURCE_ADV, CTX_RESOURCE_HMU, CTX_RESOURCE_PRF, CTX_RESOURCE_REQ, Link,
};
use crate::packet::Packet;
use crate::resource::{
    Advertisement, Incoming, Outgoing, RANDOM_HASH_LEN, content, parse_hmu, parse_proof,
    parse_request,
};
use crate::token::IV_LEN;

/// Publishes one resource over a link: advertises it, serves part requests and hashmap
/// updates, and completes when the receiver's proof of receipt arrives.
pub struct ResourceSender {
    link: Link,
    out: Outgoing,
    done: bool,
}

impl ResourceSender {
    /// Prepare to publish `data` (uncompressed) over `link`. `random_hash` salts the resource
    /// and map hashes; `iv` seals the token (it must not repeat for the link key).
    pub fn publish(
        link: Link,
        data: &[u8],
        random_hash: [u8; RANDOM_HASH_LEN],
        iv: &[u8; IV_LEN],
    ) -> Self {
        let token = link.seal(&content(data, &random_hash), iv);
        let out = Outgoing::new(data, &token, random_hash, false);
        Self {
            link,
            out,
            done: false,
        }
    }

    /// The advertisement packet, sealed. (Re)send it until the receiver responds.
    pub fn advertisement(&self, iv: &[u8; IV_LEN]) -> Packet {
        self.link
            .sealed_packet(CTX_RESOURCE_ADV, &self.out.advertisement().pack(), iv)
    }

    /// Handle one inbound packet from the receiver, returning packets to send:
    /// a request yields the requested parts (and, if it solicited more hashmap, an HMU); a
    /// valid proof completes the transfer and yields nothing.
    pub fn on_packet(
        &mut self,
        packet: &Packet,
        mut iv: impl FnMut() -> [u8; IV_LEN],
    ) -> Vec<Packet> {
        match packet.context {
            CTX_RESOURCE_REQ => {
                let Ok(plain) = self.link.decrypt(packet) else {
                    return vec![];
                };
                let Ok(req) = parse_request(&plain) else {
                    return vec![];
                };
                let mut out = Vec::new();
                // Serve every part whose map hash we hold, framed (already encrypted in-token).
                for part in self.out.serve(&req) {
                    out.push(self.link.framed_packet(CTX_RESOURCE, part));
                }
                // An exhausted request wants the next slice of the hashmap.
                if req.exhausted
                    && let Some(last) = req.last_map_hash
                {
                    let hmu = self.out.hmu_after(&last);
                    out.push(self.link.sealed_packet(CTX_RESOURCE_HMU, &hmu, &iv()));
                }
                out
            }
            CTX_RESOURCE_PRF => {
                if let Some((_, proof)) = parse_proof(&packet.payload)
                    && proof == self.out.expected_proof()
                {
                    self.done = true;
                }
                vec![]
            }
            _ => vec![],
        }
    }

    /// Whether the receiver has proved receipt.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// Receives one resource over a link: on the advertisement it requests parts, collects them,
/// solicits more hashmap when needed, then reassembles, opens, verifies, and proves.
pub struct ResourceReceiver {
    link: Link,
    inc: Option<Incoming>,
    data: Option<Vec<u8>>,
}

impl ResourceReceiver {
    /// A receiver awaiting an advertisement on `link`.
    pub fn new(link: Link) -> Self {
        Self {
            link,
            inc: None,
            data: None,
        }
    }

    /// Handle one inbound packet from the sender, returning packets to send. On the
    /// advertisement it begins the transfer and requests parts; on a part it accepts it and
    /// requests more (or proves, once complete); on an HMU it ingests the new hashes and
    /// requests the newly-known parts.
    pub fn on_packet(
        &mut self,
        packet: &Packet,
        mut iv: impl FnMut() -> [u8; IV_LEN],
    ) -> Vec<Packet> {
        match packet.context {
            CTX_RESOURCE_ADV => {
                let Ok(plain) = self.link.decrypt(packet) else {
                    return vec![];
                };
                let Ok(adv) = Advertisement::parse(&plain) else {
                    return vec![];
                };
                match Incoming::new(&adv) {
                    Ok(inc) => self.inc = Some(inc),
                    Err(_) => return vec![],
                }
                self.next_requests(&mut iv)
            }
            CTX_RESOURCE => {
                let Some(inc) = self.inc.as_mut() else {
                    return vec![];
                };
                inc.accept_part(&packet.payload);
                if inc.is_complete() {
                    self.finish()
                } else {
                    self.next_requests(&mut iv)
                }
            }
            CTX_RESOURCE_HMU => {
                let Ok(plain) = self.link.decrypt(packet) else {
                    return vec![];
                };
                let Ok(hmu) = parse_hmu(&plain) else {
                    return vec![];
                };
                if let Some(inc) = self.inc.as_mut() {
                    inc.ingest_hmu(&hmu);
                }
                self.next_requests(&mut iv)
            }
            _ => vec![],
        }
    }

    /// Re-emit the outstanding request (for loss recovery when a request or its parts were
    /// dropped). Empty once complete or before the advertisement.
    pub fn retransmit(&self, iv: impl FnMut() -> [u8; IV_LEN]) -> Vec<Packet> {
        if self.data.is_some() {
            // Already complete: re-prove in case the proof was lost.
            return self.reprove();
        }
        let mut iv = iv;
        self.next_requests(&mut iv)
    }

    /// The requests to send now: the known-but-missing parts, or a hashmap solicitation when
    /// the known hashes are collected but more parts remain.
    fn next_requests(&self, iv: &mut impl FnMut() -> [u8; IV_LEN]) -> Vec<Packet> {
        let Some(inc) = self.inc.as_ref() else {
            return vec![];
        };
        let missing = inc.missing_known();
        if !missing.is_empty() {
            vec![self
                .link
                .sealed_packet(CTX_RESOURCE_REQ, &inc.request(&missing), &iv())]
        } else if inc.needs_hmu() {
            vec![self
                .link
                .sealed_packet(CTX_RESOURCE_REQ, &inc.solicit_hmu(), &iv())]
        } else {
            vec![]
        }
    }

    /// Reassemble, open, verify, and build the proof packet. Records the payload.
    fn finish(&mut self) -> Vec<Packet> {
        let (data, payload) = {
            let inc = self.inc.as_ref().expect("complete implies an advertisement");
            let Ok(token) = inc.assemble_token() else {
                return vec![];
            };
            let Ok(decrypted) = self.link.open(&token) else {
                return vec![];
            };
            let Ok(data) = inc.recover(&decrypted) else {
                return vec![];
            };
            let mut payload = Vec::with_capacity(64);
            payload.extend_from_slice(&inc.resource_hash());
            payload.extend_from_slice(&inc.proof(&data));
            (data, payload)
        };
        self.data = Some(data);
        vec![self.link.framed_packet(CTX_RESOURCE_PRF, payload)]
    }

    /// Rebuild the proof packet for an already-recovered payload (proof retransmission).
    fn reprove(&self) -> Vec<Packet> {
        let (Some(inc), Some(data)) = (self.inc.as_ref(), self.data.as_ref()) else {
            return vec![];
        };
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&inc.resource_hash());
        payload.extend_from_slice(&inc.proof(data));
        vec![self.link.framed_packet(CTX_RESOURCE_PRF, payload)]
    }

    /// The recovered payload, once the transfer is complete and verified.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Whether the payload has been fully received and verified.
    pub fn is_complete(&self) -> bool {
        self.data.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationName;
    use crate::identity::PrivateIdentity;
    use crate::link::{LinkMode, LinkTrailer, PendingLink, accept};
    use crate::lossy::LossModel;

    /// An established link between a sender side and a receiver side.
    fn link_pair() -> (Link, Link) {
        let server = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
        let trailer = LinkTrailer {
            mode: LinkMode::Aes256Cbc,
            mtu: 500,
        };
        let dest = DestinationName::new("retinue", ["res"]).destination_hash(server.public());
        let (pending, request) = PendingLink::open(dest, *server.public(), &[0x33; 64], trailer);
        let (recv_link, proof) = accept(&request, &server, &[0x99; 64], trailer).unwrap();
        let send_link = pending.prove(&proof).unwrap();
        (send_link, recv_link)
    }

    fn iv_gen() -> impl FnMut() -> [u8; IV_LEN] {
        let mut n: u64 = 0;
        move || {
            n += 1;
            let mut v = [0u8; IV_LEN];
            v[..8].copy_from_slice(&n.to_le_bytes());
            v
        }
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect()
    }

    /// A clean transfer with no loss: advertise, request, serve, prove — end to end.
    #[test]
    fn transfers_a_small_resource() {
        let (send_link, recv_link) = link_pair();
        let data = payload(3000);
        let mut ivg = iv_gen();
        let mut sender = ResourceSender::publish(send_link, &data, [0xAB, 0xCD, 0xEF, 0x01], &ivg());
        let mut receiver = ResourceReceiver::new(recv_link);

        // The receiver gets the advertisement and drives to completion.
        let mut to_receiver = vec![sender.advertisement(&ivg())];
        let mut to_sender: Vec<Packet> = Vec::new();
        for _ in 0..100 {
            for pkt in std::mem::take(&mut to_receiver) {
                to_sender.extend(receiver.on_packet(&pkt, &mut ivg));
            }
            for pkt in std::mem::take(&mut to_sender) {
                to_receiver.extend(sender.on_packet(&pkt, &mut ivg));
            }
            if sender.is_done() && receiver.is_complete() {
                break;
            }
        }
        assert!(sender.is_done(), "sender saw the proof");
        assert_eq!(receiver.data(), Some(data.as_slice()), "payload recovered");
    }

    /// A multi-part transfer over a lossy pipe, exercising retransmission of the
    /// advertisement, requests, parts, and the proof, and the HMU path for a large hashmap.
    #[test]
    fn transfers_a_large_resource_over_loss() {
        let (send_link, recv_link) = link_pair();
        // Big enough to need many parts and stream the hashmap over more than one HMU.
        let data = payload(45_000);
        let mut ivg = iv_gen();
        let mut sender = ResourceSender::publish(send_link, &data, [0x01, 0x02, 0x03, 0x04], &ivg());
        let mut receiver = ResourceReceiver::new(recv_link);

        let mut fwd = LossModel::new(7).drop_per_mille(150).max_delay_ms(3);
        let mut bwd = LossModel::new(0x5151).drop_per_mille(150).max_delay_ms(3);
        let mut to_receiver: Vec<(u64, Packet)> = Vec::new();
        let mut to_sender: Vec<(u64, Packet)> = Vec::new();

        for now in 0..400_000u64 {
            // Retransmit on a tick: the sender re-advertises until acked; the receiver
            // re-requests what it still lacks.
            if now % 50 == 0 {
                if !sender.is_done() {
                    let adv = sender.advertisement(&ivg());
                    if !fwd.should_drop() {
                        to_receiver.push((now + 1 + fwd.delay_ms(), adv));
                    }
                }
                for pkt in receiver.retransmit(&mut ivg) {
                    if !bwd.should_drop() {
                        to_sender.push((now + 1 + bwd.delay_ms(), pkt));
                    }
                }
            }
            let mut still = Vec::new();
            for (t, pkt) in std::mem::take(&mut to_receiver) {
                if t <= now {
                    for out in receiver.on_packet(&pkt, &mut ivg) {
                        if !bwd.should_drop() {
                            to_sender.push((now + 1 + bwd.delay_ms(), out));
                        }
                    }
                } else {
                    still.push((t, pkt));
                }
            }
            to_receiver = still;
            let mut still = Vec::new();
            for (t, pkt) in std::mem::take(&mut to_sender) {
                if t <= now {
                    for out in sender.on_packet(&pkt, &mut ivg) {
                        if !fwd.should_drop() {
                            to_receiver.push((now + 1 + fwd.delay_ms(), out));
                        }
                    }
                } else {
                    still.push((t, pkt));
                }
            }
            to_sender = still;
            if sender.is_done() && receiver.is_complete() {
                break;
            }
        }
        assert!(sender.is_done(), "sender saw the proof over loss");
        assert_eq!(
            receiver.data(),
            Some(data.as_slice()),
            "large payload recovered exactly over loss"
        );
    }
}
