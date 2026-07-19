//! A reliable byte stream over a [`Link`]: RNS `Channel`/`Buffer` framing plus link-proof
//! acknowledgement, driven sans-io.
//!
//! This is the piece that makes an `AsyncRead`/`AsyncWrite` link honest on a lossy medium.
//! Over TCP the medium already never drops, so [`endpoint`](crate::endpoint) keeps its
//! best-effort stream as the default; a caller opts into this reliable path for LoRa or
//! serial, where packets drop, reorder, and delay (mode-gated, mirroring RNS, whose Channel
//! is likewise opt-in over raw link data).
//!
//! Everything here is sans-io and composes the pieces already pinned to RNS 1.3.8's wire:
//!
//! - [`Buffer`] chunks bytes into `Channel` envelopes with a windowed 16-bit sequence and a
//!   receiver-side reorder buffer (`channel.rs`, gold-tested against `channel_wire.json` /
//!   `buffer_wire.json`).
//! - Each envelope rides a link data packet under context [`CTX_CHANNEL`], sealed with the
//!   link keys.
//! - The **ack is the link packet proof** ([`Link::data_proof`] / [`Link::verify_data_proof`],
//!   gold-tested against `rns_link_proof.json`): a received packet is proved back, and an
//!   inbound proof names the packet it acknowledges by hash, releasing that sequence.
//!
//! The driver holds a `full_hash -> sequence` map so a returning proof — addressed to the
//! link, carrying the proven packet's hash — resolves to the outstanding sequence it frees.
//! It is driven by a caller (a link task): [`poll_transmit`](ReliableChannel::poll_transmit)
//! with the clock yields packets to send (new data within the window, plus retransmits);
//! [`on_data_packet`](ReliableChannel::on_data_packet) feeds a received channel packet in and
//! returns the proof to send back; [`on_proof`](ReliableChannel::on_proof) feeds a received
//! proof in. That is exactly the shape a virtual-clock loss test drives (see the tests), so
//! the reliable path is validated on the desk before any radio exists.

use std::collections::HashMap;

use crate::channel::{Buffer, Envelope};
use crate::hash::AddressHash;
use crate::identity::{Identity, PrivateIdentity};
use crate::link::{CTX_CHANNEL, Link};
use crate::packet::Packet;
use crate::token::IV_LEN;

/// A reliable, in-order byte stream over one [`Link`]. See the module docs.
pub struct ReliableChannel {
    link: Link,
    buffer: Buffer,
    /// Our identity — signs the proofs of packets we receive.
    prover: PrivateIdentity,
    /// The peer's identity — validates the proofs of packets we sent.
    peer: Identity,
    /// Full hash of each channel packet we put on the wire, to its sequence. An inbound
    /// proof carries the hash; this maps it back to the sequence to release.
    sent: HashMap<[u8; 32], u16>,
}

impl ReliableChannel {
    /// A reliable channel over `link`. `prover` is our identity (we sign proofs of packets
    /// we receive with it); `peer` is the identity we validate the peer's proofs against —
    /// for an initiator, the destination's identity from its announce.
    pub fn new(link: Link, prover: PrivateIdentity, peer: Identity) -> Self {
        Self {
            link,
            buffer: Buffer::new(),
            prover,
            peer,
            sent: HashMap::new(),
        }
    }

    /// Queue application bytes for reliable, in-order delivery.
    pub fn write(&mut self, bytes: &[u8]) {
        self.buffer.write(bytes);
    }

    /// Mark our send stream finished with an end-of-stream frame.
    pub fn finish(&mut self) {
        self.buffer.finish();
    }

    /// The channel packets to put on the wire at time `now`: newly sendable envelopes within
    /// the window and retransmits past their timeout, each sealed under [`CTX_CHANNEL`].
    /// `iv` supplies a fresh IV per packet (it must not repeat for the link key). Each
    /// packet's hash is recorded so its returning proof releases the right sequence.
    pub fn poll_transmit(&mut self, now: u64, mut iv: impl FnMut() -> [u8; IV_LEN]) -> Vec<Packet> {
        let mut out = Vec::new();
        for env in self.buffer.poll_transmit(now) {
            let packet = self.link.sealed_packet(CTX_CHANNEL, &env.encode(), &iv());
            // A retransmit re-seals with a fresh IV, so it is a new hash for the same
            // sequence; the stale entry is harmless (its packet was dropped, never proved).
            self.sent.insert(packet.full_hash(), env.sequence);
            out.push(packet);
        }
        out
    }

    /// Feed an inbound channel data packet: decrypt and order its envelope, and return the
    /// PROOF to send back — the ack. A duplicate is still proved (the peer retransmitted
    /// because our earlier proof did not arrive); [`Buffer`] drops the duplicate payload.
    /// Returns `None` only if the packet does not decrypt or carries no valid envelope.
    pub fn on_data_packet(&mut self, packet: &Packet) -> Option<Packet> {
        let plaintext = self.link.decrypt(packet).ok()?;
        let envelope = Envelope::decode(&plaintext)?;
        // Prove only what we could accept. When the reorder buffer is full, `handle` returns
        // false: we withhold the proof so the sender retransmits later, rather than proving a
        // frame we dropped (which would lose it) — this is what bounds the reorder buffer.
        self.buffer
            .handle(envelope)
            .then(|| self.link.data_proof(packet, &self.prover))
    }

    /// Feed an inbound proof: if it validates against the peer's identity and names a packet
    /// we sent, release that sequence. Returns whether it matched an outstanding packet.
    pub fn on_proof(&mut self, proof: &Packet, now: u64) -> bool {
        let Some(hash) = self.link.verify_data_proof(proof, &self.peer) else {
            return false;
        };
        let Some(sequence) = self.sent.remove(&hash) else {
            return false;
        };
        self.buffer.on_proof(sequence, now);
        true
    }

    /// Take all delivered, in-order application bytes.
    pub fn read(&mut self) -> Vec<u8> {
        self.buffer.read_available()
    }

    /// Whether the peer signalled end-of-stream.
    pub fn recv_finished(&mut self) -> bool {
        self.buffer.recv_finished()
    }

    /// Whether everything written has been sent and proven.
    pub fn send_idle(&self) -> bool {
        self.buffer.send_idle()
    }

    /// The current send window (diagnostics).
    pub fn window(&self) -> u32 {
        self.buffer.window()
    }

    /// The id of the link this stream rides.
    pub fn link_id(&self) -> AddressHash {
        self.link.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationName;
    use crate::link::{LinkMode, LinkTrailer, PendingLink, accept};
    use crate::lossy::LossModel;

    /// A client (initiator) and server (responder) reliable channel over one established
    /// link, each holding the other's identity for proof validation.
    fn pair() -> (ReliableChannel, ReliableChannel) {
        let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
        let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let trailer = LinkTrailer {
            mode: LinkMode::Aes256Cbc,
            mtu: 500,
        };
        let dest = DestinationName::new("retinue", ["test"]).destination_hash(server_id.public());
        let (pending, request) = PendingLink::open(dest, *server_id.public(), &[0x33; 64], trailer);
        let (responder_link, proof) = accept(&request, &server_id, &[0x99; 64], trailer).unwrap();
        let initiator_link = pending.prove(&proof).unwrap();

        let client = ReliableChannel::new(initiator_link, client_id.clone(), *server_id.public());
        let server = ReliableChannel::new(responder_link, server_id, *client_id.public());
        (client, server)
    }

    /// Drive `client`'s payload to `server` over a lossy pipe on a virtual clock: channel
    /// packets forward (subject to loss), proofs back (subject to loss), retransmits on the
    /// clock. Asserts exact, in-order reconstruction and that the server saw eof.
    fn drive_over_loss(drop_per_mille: u32, max_delay: u64, seed: u64, len: usize) {
        let (mut client, mut server) = pair();
        let payload: Vec<u8> = (0..len as u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        client.write(&payload);
        client.finish();

        let mut fwd = LossModel::new(seed)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay);
        let mut bwd = LossModel::new(seed ^ 0xABCD)
            .drop_per_mille(drop_per_mille)
            .max_delay_ms(max_delay);

        let mut to_server: Vec<(u64, Packet)> = Vec::new();
        let mut to_client: Vec<(u64, Packet)> = Vec::new();
        let mut got: Vec<u8> = Vec::new();
        let mut ivc: u64 = 0;

        for now in 0..2_000_000u64 {
            let mut iv = || {
                ivc += 1;
                let mut v = [0u8; IV_LEN];
                v[..8].copy_from_slice(&ivc.to_le_bytes());
                v
            };
            for pkt in client.poll_transmit(now, &mut iv) {
                if !fwd.should_drop() {
                    to_server.push((now + 1 + fwd.delay_ms(), pkt));
                }
            }
            let mut still = Vec::new();
            for (t, pkt) in std::mem::take(&mut to_server) {
                if t <= now {
                    if let Some(proof) = server.on_data_packet(&pkt)
                        && !bwd.should_drop()
                    {
                        to_client.push((now + 1 + bwd.delay_ms(), proof));
                    }
                } else {
                    still.push((t, pkt));
                }
            }
            to_server = still;
            to_client.retain(|(t, proof)| {
                if *t <= now {
                    client.on_proof(proof, now);
                    false
                } else {
                    true
                }
            });
            got.extend(server.read());
            if got.len() == payload.len() && client.send_idle() {
                break;
            }
        }
        assert_eq!(
            got, payload,
            "reliable stream must reconstruct exactly over loss"
        );
        assert!(server.recv_finished(), "server saw the client's eof");
    }

    #[test]
    fn reliable_stream_is_faithful_without_loss() {
        drive_over_loss(0, 0, 1, 5000);
    }

    #[test]
    fn reliable_stream_survives_drop() {
        drive_over_loss(300, 0, 7, 5000);
    }

    #[test]
    fn reliable_stream_survives_drop_reorder_and_delay() {
        drive_over_loss(250, 6, 42, 4000);
    }

    #[test]
    fn reliable_stream_survives_heavy_loss() {
        drive_over_loss(600, 3, 99, 3000);
    }

    #[test]
    fn a_forged_proof_releases_nothing() {
        // A proof signed by the wrong identity, or naming a packet we never sent, must not
        // release an outstanding sequence.
        let (mut client, mut server) = pair();
        client.write(b"one small message that fits in a single channel packet");
        let mut ivc = 0u64;
        let mut iv = || {
            ivc += 1;
            let mut v = [0u8; IV_LEN];
            v[..8].copy_from_slice(&ivc.to_le_bytes());
            v
        };
        let sent = client.poll_transmit(0, &mut iv);
        assert!(!sent.is_empty());
        server.on_data_packet(&sent[0]).unwrap();

        // A proof from a stranger's identity over the right hash: rejected (wrong signer).
        let stranger = PrivateIdentity::from_secret_bytes(&[0x55; 64]);
        let forged = client.link.data_proof(&sent[0], &stranger);
        assert!(
            !client.on_proof(&forged, 1),
            "wrong-identity proof rejected"
        );
        assert!(!client.send_idle(), "the packet is still outstanding");

        // The genuine proof (server signs with its identity) does release it.
        let real = server.on_data_packet(&sent[0]).unwrap();
        assert!(client.on_proof(&real, 2), "genuine proof accepted");
    }
}
