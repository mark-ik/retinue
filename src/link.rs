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

use x25519_dalek::PublicKey as XPublicKey;

use crate::hash::AddressHash;
use crate::identity::{Identity, KEY_LEN, PrivateIdentity, SIGNATURE_LEN};
use crate::packet::{
    DestinationType, HeaderType, Packet, PacketType, Propagation,
};
use crate::token::{DerivedKeys, IV_LEN};
use crate::{Error, Result};

/// Length of the mode/MTU trailer on link requests and proofs.
pub const TRAILER_LEN: usize = 3;

/// Bytes of key material in a link request: two 32-byte public keys.
pub const LINK_KEYS_LEN: usize = 64;

/// Bytes of a link request: the keys plus the trailer.
pub const LINK_REQUEST_LEN: usize = LINK_KEYS_LEN + TRAILER_LEN;

/// Bytes of a link proof: signature (64), public key (32), and the trailer.
pub const LINK_PROOF_LEN: usize = SIGNATURE_LEN + KEY_LEN + TRAILER_LEN;

/// Packet context byte for a link request proof.
pub const CTX_LRPROOF: u8 = 0xff;

/// Packet context byte for the link RTT packet.
pub const CTX_LRRTT: u8 = 0xfe;

/// Packet context byte for a keepalive.
pub const CTX_KEEPALIVE: u8 = 0xfa;

/// Packet context byte for a link close.
pub const CTX_LINKCLOSE: u8 = 0xfc;

/// Packet context byte for a request over a link.
pub const CTX_REQUEST: u8 = 0x09;

/// Packet context byte for a response over a link.
pub const CTX_RESPONSE: u8 = 0x0a;

/// Resource context bytes. See [`crate::resource`].
pub const CTX_RESOURCE: u8 = 0x01;
/// Resource advertisement.
pub const CTX_RESOURCE_ADV: u8 = 0x02;
/// Resource part request.
pub const CTX_RESOURCE_REQ: u8 = 0x03;
/// Resource hashmap update.
pub const CTX_RESOURCE_HMU: u8 = 0x04;
/// Resource proof.
pub const CTX_RESOURCE_PRF: u8 = 0x05;
/// Resource initiator cancel.
pub const CTX_RESOURCE_ICL: u8 = 0x06;
/// Resource receiver cancel.
pub const CTX_RESOURCE_RCL: u8 = 0x07;

/// Keepalive request/response sentinels, carried as the single plaintext byte of a
/// keepalive packet.
pub const KEEPALIVE_REQUEST: u8 = 0xff;
pub const KEEPALIVE_RESPONSE: u8 = 0xfe;

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

/// Build the flag/hops/dest/context prefix and payload of a link-layer packet.
fn link_packet(context: u8, link_id: AddressHash, payload: Vec<u8>) -> Packet {
    Packet {
        ifac: false,
        header_type: HeaderType::Type1,
        context_flag: false,
        propagation: Propagation::Broadcast,
        destination_type: DestinationType::Link,
        packet_type: PacketType::Data,
        hops: 0,
        transport: None,
        destination: link_id,
        context,
        payload,
    }
}

/// An outbound link the initiator has requested but the peer has not yet proved.
///
/// Holds the ephemeral secret so the shared key can be derived once the proof arrives. A
/// `PendingLink` becomes a [`Link`] only through [`prove`](PendingLink::prove), which
/// verifies the peer's signature first.
pub struct PendingLink {
    ephemeral: PrivateIdentity,
    peer: Identity,
    link_id: AddressHash,
    requested: LinkTrailer,
}

impl PendingLink {
    /// Start a link to `peer` at `destination`.
    ///
    /// `ephemeral` is a fresh 64-byte keypair seed (`x25519_secret(32) ||
    /// ed25519_seed(32)`), generated per attempt by the caller: R3 stays RNG-free the same
    /// way R0 does, so this is reproducible and the runtime supplies the randomness.
    /// Returns the pending link and the request packet to send.
    pub fn open(
        destination: AddressHash,
        peer: Identity,
        ephemeral_seed: &[u8; 64],
        requested: LinkTrailer,
    ) -> (Self, Packet) {
        let ephemeral = PrivateIdentity::from_secret_bytes(ephemeral_seed);

        let mut payload = Vec::with_capacity(LINK_REQUEST_LEN);
        payload.extend_from_slice(&ephemeral.public().to_public_bytes());
        payload.extend_from_slice(&requested.encode());

        let request = Packet {
            ifac: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            propagation: Propagation::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::LinkRequest,
            hops: 0,
            transport: None,
            destination,
            context: 0,
            payload,
        };

        let link_id = link_id(&request).expect("request we just built has 64+ payload bytes");
        (
            Self {
                ephemeral,
                peer,
                link_id,
                requested,
            },
            request,
        )
    }

    /// The link id this attempt will have. Inbound proofs are addressed to it.
    pub fn link_id(&self) -> AddressHash {
        self.link_id
    }

    /// Validate a proof and, if it checks out, produce the established [`Link`].
    ///
    /// The proof is `signature(64) || peer_ephemeral_x25519(32) || trailer(3)`. The
    /// signature covers `link_id || peer_ephemeral_x25519 || peer_identity_ed25519 ||
    /// trailer`, which binds the ephemeral key to the destination's long-term identity, so
    /// a third party cannot substitute its own ephemeral key. Verified against RNS 1.3.8.
    pub fn prove(&self, proof: &Packet) -> Result<Link> {
        if proof.packet_type != PacketType::Proof {
            return Err(Error::NotAProof);
        }
        if proof.destination != self.link_id {
            return Err(Error::LinkMismatch);
        }
        if proof.payload.len() < SIGNATURE_LEN + KEY_LEN {
            return Err(Error::Truncated);
        }

        let signature: [u8; SIGNATURE_LEN] =
            proof.payload[..SIGNATURE_LEN].try_into().expect("checked length");
        let peer_eph: [u8; KEY_LEN] = proof.payload[SIGNATURE_LEN..SIGNATURE_LEN + KEY_LEN]
            .try_into()
            .expect("checked length");
        let trailer_bytes = &proof.payload[SIGNATURE_LEN + KEY_LEN..];

        // The signed message ends with the trailer when the proof carries one.
        let mut signed = Vec::with_capacity(
            crate::hash::ADDRESS_HASH_LEN + KEY_LEN + KEY_LEN + trailer_bytes.len(),
        );
        signed.extend_from_slice(self.link_id.as_slice());
        signed.extend_from_slice(&peer_eph);
        signed.extend_from_slice(self.peer.ed25519_bytes());
        signed.extend_from_slice(trailer_bytes);

        if !self.peer.verify(&signed, &signature) {
            return Err(Error::BadSignature);
        }

        // The proof's trailer is authoritative for the negotiated mode and MTU; fall back
        // to what we requested if the peer sent none.
        let agreed = if trailer_bytes.len() >= TRAILER_LEN {
            LinkTrailer::decode(trailer_bytes[..TRAILER_LEN].try_into().expect("len"))?
        } else {
            self.requested
        };

        let shared = self.ephemeral.diffie_hellman(&XPublicKey::from(peer_eph));
        let keys = DerivedKeys::derive(&shared, self.link_id);

        Ok(Link {
            id: self.link_id,
            keys,
            mode: agreed.mode,
            mtu: agreed.mtu,
        })
    }
}

/// Accept an inbound link request and produce the proof.
///
/// This is the responder mirror of [`PendingLink`]. The destination signs the proof with
/// its long-term identity (so the initiator, which learned that identity from an announce,
/// can bind the ephemeral key to it), and contributes a fresh ephemeral X25519 key for the
/// exchange. Returns the established [`Link`] and the proof packet to send back.
///
/// `ephemeral_seed` is a fresh 64-byte keypair seed supplied by the caller; only its
/// X25519 half is used here. `offered` is the mode and MTU to advertise, capped by the
/// caller against the request if it wants to honour the initiator's proposal.
pub fn accept(
    request: &Packet,
    destination: &PrivateIdentity,
    ephemeral_seed: &[u8; 64],
    offered: LinkTrailer,
) -> Result<(Link, Packet)> {
    if request.packet_type != PacketType::LinkRequest {
        return Err(Error::NotALinkRequest);
    }
    if request.payload.len() < LINK_KEYS_LEN {
        return Err(Error::Truncated);
    }

    let id = link_id(request)?;
    let peer_eph_x: [u8; KEY_LEN] =
        request.payload[..KEY_LEN].try_into().expect("checked length");

    let ephemeral = PrivateIdentity::from_secret_bytes(ephemeral_seed);
    let our_eph_x = *ephemeral.public().x25519_bytes();
    let trailer = offered.encode();

    // Sign link_id || our_eph_x || our_long_term_ed25519 || trailer with the destination's
    // identity, exactly as the initiator will reconstruct and verify it.
    let mut signed = Vec::with_capacity(
        crate::hash::ADDRESS_HASH_LEN + KEY_LEN + KEY_LEN + TRAILER_LEN,
    );
    signed.extend_from_slice(id.as_slice());
    signed.extend_from_slice(&our_eph_x);
    signed.extend_from_slice(destination.public().ed25519_bytes());
    signed.extend_from_slice(&trailer);
    let signature = destination.sign(&signed);

    let mut payload = Vec::with_capacity(LINK_PROOF_LEN);
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(&our_eph_x);
    payload.extend_from_slice(&trailer);

    let proof = Packet {
        ifac: false,
        header_type: HeaderType::Type1,
        context_flag: false,
        propagation: Propagation::Broadcast,
        destination_type: DestinationType::Link,
        packet_type: PacketType::Proof,
        hops: 0,
        transport: None,
        destination: id,
        context: CTX_LRPROOF,
        payload,
    };

    let shared = ephemeral.diffie_hellman(&XPublicKey::from(peer_eph_x));
    let keys = DerivedKeys::derive(&shared, id);

    Ok((
        Link {
            id,
            keys,
            mode: offered.mode,
            mtu: offered.mtu,
        },
        proof,
    ))
}

/// What an inbound link-layer packet is, once matched to a link by its id.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// Application data, already decrypted.
    Data(Vec<u8>),
    /// The RTT packet that follows a proof. Its contents are not load-bearing.
    Rtt,
    /// A keepalive request. Answer it with [`Link::keepalive_packet`] carrying
    /// [`KEEPALIVE_RESPONSE`].
    KeepAliveRequest,
    /// A keepalive response to one we sent.
    KeepAliveResponse,
    /// The peer tore the link down.
    Close,
    /// A request, already decrypted. The payload is RNS's msgpack-packed request.
    Request(Vec<u8>),
    /// A response, already decrypted. The payload is RNS's msgpack-packed response.
    Response(Vec<u8>),
    /// Addressed to this link but not a shape we recognise.
    Unknown,
}

/// An established link: a shared key and the negotiated parameters.
///
/// The data channel is the R0 token with the link's static key. There is no per-packet
/// ECDH and no ephemeral prefix, because the forward secrecy already lives in the ephemeral
/// key exchange that established the link. This is why links carry no ratchet.
pub struct Link {
    id: AddressHash,
    keys: DerivedKeys,
    mode: LinkMode,
    mtu: u32,
}

impl Link {
    pub fn id(&self) -> AddressHash {
        self.id
    }

    pub fn mode(&self) -> LinkMode {
        self.mode
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Encrypt application bytes into a link data packet.
    ///
    /// `iv` is caller-supplied to keep this reproducible; it must be fresh and
    /// unpredictable per packet in production.
    pub fn data_packet(&self, plaintext: &[u8], iv: &[u8; IV_LEN]) -> Packet {
        link_packet(0x00, self.id, self.keys.encrypt(plaintext, iv))
    }

    /// Decrypt a link data packet's payload.
    pub fn decrypt(&self, packet: &Packet) -> Result<Vec<u8>> {
        self.keys.decrypt(&packet.payload)
    }

    /// Seal a whole blob with the link keys into one token (`IV || ciphertext || HMAC`).
    ///
    /// Resources encrypt the compressed payload as a single token, then split *that* into
    /// parts, so the resource layer needs blob crypto rather than per-packet crypto.
    pub fn seal(&self, plaintext: &[u8], iv: &[u8; IV_LEN]) -> Vec<u8> {
        self.keys.encrypt(plaintext, iv)
    }

    /// Open a whole blob sealed with [`seal`](Self::seal).
    pub fn open(&self, token: &[u8]) -> Result<Vec<u8>> {
        self.keys.decrypt(token)
    }

    /// A link packet with an arbitrary context and an already-encrypted payload.
    ///
    /// Resource parts carry raw slices of a pre-sealed token, so they are not encrypted
    /// again; the advertisement/request/proof, which are sealed, pass their token here too.
    pub fn framed_packet(&self, context: u8, payload: Vec<u8>) -> Packet {
        link_packet(context, self.id, payload)
    }

    /// A link packet whose plaintext is sealed with the link keys under `context`.
    pub fn sealed_packet(&self, context: u8, plaintext: &[u8], iv: &[u8; IV_LEN]) -> Packet {
        link_packet(context, self.id, self.keys.encrypt(plaintext, iv))
    }

    /// A resource proof packet: a `Proof`-type packet on this link, context
    /// `RESOURCE_PRF`, payload `resource_hash(32) || proof(32)`, sent unencrypted. This is
    /// the shape RNS 1.3.8 accepts to conclude a resource transfer (verified live).
    pub fn resource_proof_packet(&self, resource_hash: &[u8; 32], proof: &[u8; 32]) -> Packet {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(resource_hash);
        payload.extend_from_slice(proof);
        Packet {
            ifac: false,
            header_type: HeaderType::Type1,
            context_flag: false,
            propagation: Propagation::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
            hops: 0,
            transport: None,
            destination: self.id,
            context: CTX_RESOURCE_PRF,
            payload,
        }
    }

    /// Classify an inbound packet addressed to this link.
    ///
    /// Returns `None` if the packet is not for this link at all. Otherwise it dispatches on
    /// the context byte: data and RTT are decrypted, keepalives and closes are recognised
    /// by their shape.
    pub fn receive(&self, packet: &Packet) -> Option<Inbound> {
        if packet.destination != self.id {
            return None;
        }
        Some(match packet.context {
            0x00 => match self.decrypt(packet) {
                Ok(data) => Inbound::Data(data),
                Err(_) => Inbound::Unknown,
            },
            CTX_LRRTT => Inbound::Rtt,
            CTX_REQUEST => match self.decrypt(packet) {
                Ok(data) => Inbound::Request(data),
                Err(_) => Inbound::Unknown,
            },
            CTX_RESPONSE => match self.decrypt(packet) {
                Ok(data) => Inbound::Response(data),
                Err(_) => Inbound::Unknown,
            },
            CTX_KEEPALIVE => match packet.payload.first().copied() {
                Some(KEEPALIVE_REQUEST) => Inbound::KeepAliveRequest,
                Some(KEEPALIVE_RESPONSE) => Inbound::KeepAliveResponse,
                _ => Inbound::Unknown,
            },
            CTX_LINKCLOSE => Inbound::Close,
            _ => Inbound::Unknown,
        })
    }

    /// The RTT packet the initiator sends after a proof, which moves the link to active on
    /// the peer. RNS expects a msgpack-encoded float; the exact value is not load-bearing.
    pub fn rtt_packet(&self, rtt_seconds: f32, iv: &[u8; IV_LEN]) -> Packet {
        // msgpack float32: 0xca then big-endian bytes.
        let mut plain = Vec::with_capacity(5);
        plain.push(0xca);
        plain.extend_from_slice(&rtt_seconds.to_be_bytes());
        link_packet(CTX_LRRTT, self.id, self.keys.encrypt(&plain, iv))
    }

    /// Encrypt an already-packed request into a link request packet (context `0x09`).
    ///
    /// The `packed` bytes are RNS's msgpack request structure; retinue does not impose one,
    /// so a caller can carry whatever the peer expects. See [`crate::request`].
    pub fn request_packet(&self, packed: &[u8], iv: &[u8; IV_LEN]) -> Packet {
        link_packet(CTX_REQUEST, self.id, self.keys.encrypt(packed, iv))
    }

    /// Encrypt an already-packed response into a link response packet (context `0x0a`).
    pub fn response_packet(&self, packed: &[u8], iv: &[u8; IV_LEN]) -> Packet {
        link_packet(CTX_RESPONSE, self.id, self.keys.encrypt(packed, iv))
    }

    /// A keepalive. The peer answers a [`KEEPALIVE_REQUEST`] with a [`KEEPALIVE_RESPONSE`].
    /// Keepalive bytes are not encrypted; they ride the link by its id alone.
    pub fn keepalive_packet(&self, sentinel: u8) -> Packet {
        link_packet(CTX_KEEPALIVE, self.id, vec![sentinel])
    }

    /// Tear the link down.
    pub fn close_packet(&self) -> Packet {
        link_packet(CTX_LINKCLOSE, self.id, self.id.as_slice().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationName;

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

    /// Initiator and responder, both retinue, must agree on the link id and the session
    /// key, and then talk. This checks the two sides are mutually consistent; the oracle
    /// gates check each side against RNS.
    #[test]
    fn initiator_and_responder_agree() {
        let dest_identity = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let peer = *dest_identity.public();
        let dest_hash =
            DestinationName::new("retinue", ["test"]).destination_hash(&peer);

        let trailer = LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 };

        // Initiator opens.
        let (pending, request) =
            PendingLink::open(dest_hash, peer, &[0x33; 64], trailer);

        // Responder accepts and proves.
        let (responder_link, proof) =
            accept(&request, &dest_identity, &[0x99; 64], trailer).unwrap();

        // Initiator verifies the proof and establishes.
        let initiator_link = pending.prove(&proof).unwrap();

        assert_eq!(initiator_link.id(), responder_link.id());
        assert_eq!(initiator_link.id(), pending.link_id());

        // The shared key round-trips: what one encrypts, the other decrypts.
        let msg = b"across the link";
        let packet = initiator_link.data_packet(msg, &[0x01; 16]);
        assert_eq!(responder_link.receive(&packet), Some(Inbound::Data(msg.to_vec())));

        let back = responder_link.data_packet(b"and back", &[0x02; 16]);
        assert_eq!(
            initiator_link.receive(&back),
            Some(Inbound::Data(b"and back".to_vec())),
        );
    }

    #[test]
    fn receive_classifies_link_traffic() {
        let dest_identity = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
        let (_pending, request) = PendingLink::open(
            DestinationName::new("retinue", ["test"]).destination_hash(dest_identity.public()),
            *dest_identity.public(),
            &[0x33; 64],
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
        );
        let (link, _proof) = accept(
            &request,
            &dest_identity,
            &[0x99; 64],
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
        )
        .unwrap();

        assert_eq!(
            link.receive(&link.keepalive_packet(KEEPALIVE_REQUEST)),
            Some(Inbound::KeepAliveRequest),
        );
        assert_eq!(
            link.receive(&link.keepalive_packet(KEEPALIVE_RESPONSE)),
            Some(Inbound::KeepAliveResponse),
        );
        assert_eq!(link.receive(&link.close_packet()), Some(Inbound::Close));

        // A packet for a different link id is not ours.
        let mut foreign = link.keepalive_packet(KEEPALIVE_REQUEST);
        foreign.destination = AddressHash::from_bytes([0xAB; 16]);
        assert_eq!(link.receive(&foreign), None);
    }
}
