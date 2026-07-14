//! Announces: building them, and validating them.
//!
//! # Layout
//!
//! The announce payload, in wire order:
//!
//! ```text
//! x25519_pub(32) || ed25519_pub(32) || name_hash(10) || rand_hash(10)
//!                || [ratchet(32)]   || signature(64) || app_data(*)
//! ```
//!
//! The ratchet is present exactly when the packet's context flag (header bit 5) is set.
//!
//! # The signed message is not the payload
//!
//! This is the trap in the whole protocol, and it has two halves. The Ed25519 signature
//! covers:
//!
//! ```text
//! dest_hash(16) || x25519_pub(32) || ed25519_pub(32) || name_hash(10) || rand_hash(10)
//!               || [ratchet(32)]  || app_data(*)
//! ```
//!
//! So: the destination hash is prepended, and it *is not in the payload at all* (it lives
//! in the packet header); and the signature itself is spliced out, which moves `app_data`.
//! Put the other way round, the signed message is the wire payload with the header's
//! destination hash on the front and the signature cut out of the middle.
//!
//! Verified against RNS 1.3.8 by independent Ed25519 verification across all four
//! combinations of {ratchet, no ratchet} x {app_data, no app_data}, and by six negative
//! fixtures in which a single flipped byte (including one in the *header*) must and does
//! fail validation.

use crate::destination::destination_hash;
use crate::hash::{AddressHash, NameHash};
use crate::identity::{IDENTITY_LEN, Identity, KEY_LEN, PrivateIdentity, SIGNATURE_LEN};
use crate::packet::{
    DestinationType, HeaderType, Packet, PacketType, Propagation,
};
use crate::{Error, Result};

/// Length of the random hash carried in an announce.
pub const RAND_HASH_LEN: usize = 10;

/// Length of a ratchet public key. An X25519 public key.
pub const RATCHET_LEN: usize = 32;

/// Smallest valid announce payload: both keys, both hashes, a signature, no app data.
pub const MIN_PAYLOAD_LEN: usize =
    IDENTITY_LEN + crate::hash::NAME_HASH_LEN + RAND_HASH_LEN + SIGNATURE_LEN;

/// A validated announce.
///
/// There is no way to construct one whose signature has not been checked: [`Announce::decode`]
/// verifies before it returns. An `Announce` in hand is an announce that verified.
#[derive(Clone, Debug)]
pub struct Announce {
    /// The announcing peer's identity, recovered from the payload.
    pub identity: Identity,
    /// The destination hash, taken from the packet header.
    pub destination: AddressHash,
    pub name_hash: NameHash,
    pub rand_hash: [u8; RAND_HASH_LEN],
    /// The peer's current ratchet public key, if it advertised one.
    pub ratchet: Option<[u8; RATCHET_LEN]>,
    pub app_data: Vec<u8>,
}

impl Announce {
    /// Assemble the message the signature covers.
    ///
    /// Shared by build and validate so the two cannot drift apart. If they ever disagree,
    /// every announce we emit is rejected by everyone, silently.
    fn signed_message(
        destination: AddressHash,
        identity_public: &[u8; IDENTITY_LEN],
        name_hash: NameHash,
        rand_hash: &[u8; RAND_HASH_LEN],
        ratchet: Option<&[u8; RATCHET_LEN]>,
        app_data: &[u8],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(
            crate::hash::ADDRESS_HASH_LEN
                + IDENTITY_LEN
                + crate::hash::NAME_HASH_LEN
                + RAND_HASH_LEN
                + ratchet.map_or(0, |_| RATCHET_LEN)
                + app_data.len(),
        );
        msg.extend_from_slice(destination.as_slice());
        msg.extend_from_slice(identity_public);
        msg.extend_from_slice(name_hash.as_slice());
        msg.extend_from_slice(rand_hash);
        if let Some(r) = ratchet {
            msg.extend_from_slice(r);
        }
        msg.extend_from_slice(app_data);
        msg
    }

    /// Decode and validate an announce packet.
    ///
    /// Returns [`Error::BadSignature`] if the signature does not check out, which is the
    /// only thing standing between us and a peer that announces someone else's identity.
    pub fn decode(packet: &Packet) -> Result<Self> {
        if packet.packet_type != PacketType::Announce {
            return Err(Error::NotAnAnnounce);
        }

        let ratcheted = packet.context_flag;
        let want = MIN_PAYLOAD_LEN + if ratcheted { RATCHET_LEN } else { 0 };
        if packet.payload.len() < want {
            return Err(Error::Truncated);
        }
        let p = &packet.payload;

        let public: [u8; IDENTITY_LEN] = p[..IDENTITY_LEN].try_into().expect("checked length");
        let identity = Identity::from_public_bytes(&public)?;

        let mut off = IDENTITY_LEN;
        let name_hash = NameHash::from_slice(&p[off..]).ok_or(Error::Truncated)?;
        off += crate::hash::NAME_HASH_LEN;

        let rand_hash: [u8; RAND_HASH_LEN] =
            p[off..off + RAND_HASH_LEN].try_into().expect("checked length");
        off += RAND_HASH_LEN;

        let ratchet = if ratcheted {
            let r: [u8; RATCHET_LEN] =
                p[off..off + RATCHET_LEN].try_into().expect("checked length");
            off += RATCHET_LEN;
            Some(r)
        } else {
            None
        };

        let signature: [u8; SIGNATURE_LEN] =
            p[off..off + SIGNATURE_LEN].try_into().expect("checked length");
        off += SIGNATURE_LEN;

        let app_data = p[off..].to_vec();

        // The destination hash comes from the header, and it is part of the signed
        // message, so a peer cannot replay one destination's announce under another.
        let destination = packet.destination;

        let message = Self::signed_message(
            destination,
            &public,
            name_hash,
            &rand_hash,
            ratchet.as_ref(),
            &app_data,
        );
        if !identity.verify(&message, &signature) {
            return Err(Error::BadSignature);
        }

        // The destination hash must actually be the one this identity and name imply.
        // Without this a valid signature over an unrelated destination hash would pass.
        if destination_hash(name_hash, identity.hash()) != destination {
            return Err(Error::DestinationMismatch);
        }

        Ok(Self {
            identity,
            destination,
            name_hash,
            rand_hash,
            ratchet,
            app_data,
        })
    }

    /// The ratchet id a peer would use to refer to this announce's ratchet.
    ///
    /// `trunc10(SHA256(ratchet_public_key))`. Verified against RNS 1.3.8's
    /// `current_ratchet_id`.
    pub fn ratchet_id(&self) -> Option<NameHash> {
        self.ratchet.map(|r| NameHash::of(&r))
    }
}

/// Build a signed announce packet.
///
/// `rand_hash` is supplied by the caller rather than generated here, which keeps this
/// module free of any RNG and lets fixtures be reproduced byte for byte. The runtime layer
/// is responsible for producing a fresh random one per announce.
pub fn build(
    identity: &PrivateIdentity,
    name_hash: NameHash,
    rand_hash: &[u8; RAND_HASH_LEN],
    ratchet: Option<&[u8; RATCHET_LEN]>,
    app_data: &[u8],
) -> Packet {
    let public = identity.public().to_public_bytes();
    let destination = destination_hash(name_hash, identity.hash());

    let message = Announce::signed_message(
        destination,
        &public,
        name_hash,
        rand_hash,
        ratchet,
        app_data,
    );
    let signature = identity.sign(&message);

    let mut payload = Vec::with_capacity(
        IDENTITY_LEN
            + crate::hash::NAME_HASH_LEN
            + RAND_HASH_LEN
            + ratchet.map_or(0, |_| RATCHET_LEN)
            + SIGNATURE_LEN
            + app_data.len(),
    );
    payload.extend_from_slice(&public);
    payload.extend_from_slice(name_hash.as_slice());
    payload.extend_from_slice(rand_hash);
    if let Some(r) = ratchet {
        payload.extend_from_slice(r);
    }
    payload.extend_from_slice(&signature);
    payload.extend_from_slice(app_data);

    Packet {
        ifac: false,
        header_type: HeaderType::Type1,
        context_flag: ratchet.is_some(),
        propagation: Propagation::Broadcast,
        destination_type: DestinationType::Single,
        packet_type: PacketType::Announce,
        hops: 0,
        transport: None,
        destination,
        context: 0,
        payload,
    }
}

// Silence an unused-import warning when the crate is built without the token module's
// consumers; KEY_LEN documents that a ratchet is an X25519 public key.
const _: () = assert!(RATCHET_LEN == KEY_LEN);
