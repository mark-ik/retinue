//! ADVERT payloads: a node advertising its identity.
//!
//! Wire layout inside a `PAYLOAD_TYPE_ADVERT` packet payload:
//!
//! ```text
//! [pub_key 32] [timestamp u32 LE] [signature 64] [app_data 0..=32]
//! ```
//!
//! The signature covers `pub_key || timestamp || app_data` (everything except
//! itself). Receivers drop adverts whose signature does not verify.
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use crate::identity::{Identity, LocalIdentity};
use crate::packet::{PUB_KEY_SIZE, SIGNATURE_SIZE};

/// Maximum app-data bytes carried by an advert.
pub const MAX_ADVERT_DATA: usize = 32;

/// A decoded, signature-verified advert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub identity: Identity,
    /// Sender's clock at emission, seconds (u32, little-endian on the wire).
    pub timestamp: u32,
    pub app_data: Vec<u8>,
}

impl Advert {
    /// Build and sign an advert payload, ready to place in an ADVERT packet.
    /// Returns `None` if `app_data` exceeds [`MAX_ADVERT_DATA`].
    pub fn encode(id: &LocalIdentity, timestamp: u32, app_data: &[u8]) -> Option<Vec<u8>> {
        if app_data.len() > MAX_ADVERT_DATA {
            return None;
        }
        let pub_key = id.identity().pub_key;
        let mut message = Vec::with_capacity(PUB_KEY_SIZE + 4 + app_data.len());
        message.extend_from_slice(&pub_key);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(app_data);
        let sig = id.sign(&message);

        let mut out = Vec::with_capacity(PUB_KEY_SIZE + 4 + SIGNATURE_SIZE + app_data.len());
        out.extend_from_slice(&pub_key);
        out.extend_from_slice(&timestamp.to_le_bytes());
        out.extend_from_slice(&sig);
        out.extend_from_slice(app_data);
        Some(out)
    }

    /// Decode an ADVERT packet payload and verify its signature. `None` for
    /// truncated payloads or forged signatures. App data beyond
    /// [`MAX_ADVERT_DATA`] is truncated before verification, as upstream does.
    pub fn decode(payload: &[u8]) -> Option<Advert> {
        let mut i = 0;
        let pub_key: [u8; PUB_KEY_SIZE] = payload.get(i..i + PUB_KEY_SIZE)?.try_into().ok()?;
        i += PUB_KEY_SIZE;
        let timestamp = u32::from_le_bytes(payload.get(i..i + 4)?.try_into().ok()?);
        i += 4;
        let sig = payload.get(i..i + SIGNATURE_SIZE)?;
        i += SIGNATURE_SIZE;
        let mut app_data = &payload[i..];
        if app_data.len() > MAX_ADVERT_DATA {
            app_data = &app_data[..MAX_ADVERT_DATA];
        }

        let identity = Identity::new(pub_key);
        let mut message = Vec::with_capacity(PUB_KEY_SIZE + 4 + app_data.len());
        message.extend_from_slice(&pub_key);
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(app_data);
        if !identity.verify(sig, &message) {
            return None;
        }

        Some(Advert {
            identity,
            timestamp,
            app_data: app_data.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn li() -> LocalIdentity {
        LocalIdentity::from_seed([42u8; 32])
    }

    #[test]
    fn roundtrip() {
        let wire = Advert::encode(&li(), 1_752_969_600, b"Mark's node").unwrap();
        let adv = Advert::decode(&wire).unwrap();
        assert_eq!(adv.identity, li().identity());
        assert_eq!(adv.timestamp, 1_752_969_600);
        assert_eq!(adv.app_data, b"Mark's node");
    }

    #[test]
    fn timestamp_is_little_endian() {
        let wire = Advert::encode(&li(), 0x0102_0304, b"").unwrap();
        assert_eq!(&wire[PUB_KEY_SIZE..PUB_KEY_SIZE + 4], &[4, 3, 2, 1]);
    }

    #[test]
    fn tampered_app_data_rejected() {
        let mut wire = Advert::encode(&li(), 5, b"honest").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0xFF;
        assert!(Advert::decode(&wire).is_none());
    }

    #[test]
    fn tampered_timestamp_rejected() {
        let mut wire = Advert::encode(&li(), 5, b"x").unwrap();
        wire[PUB_KEY_SIZE] ^= 1;
        assert!(Advert::decode(&wire).is_none());
    }

    #[test]
    fn truncated_rejected() {
        let wire = Advert::encode(&li(), 5, b"").unwrap();
        assert!(Advert::decode(&wire[..wire.len() - 1]).is_none());
    }

    #[test]
    fn oversize_app_data_refused_on_encode() {
        assert!(Advert::encode(&li(), 5, &[0u8; MAX_ADVERT_DATA + 1]).is_none());
    }

    #[test]
    fn empty_app_data_ok() {
        let wire = Advert::encode(&li(), 9, b"").unwrap();
        assert_eq!(wire.len(), PUB_KEY_SIZE + 4 + SIGNATURE_SIZE);
        assert!(Advert::decode(&wire).is_some());
    }
}
