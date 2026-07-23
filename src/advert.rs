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

pub const ADVERT_TYPE_NONE: u8 = 0;
pub const ADVERT_TYPE_CHAT: u8 = 1;
pub const ADVERT_TYPE_REPEATER: u8 = 2;
pub const ADVERT_TYPE_ROOM: u8 = 3;
pub const ADVERT_TYPE_SENSOR: u8 = 4;

const TYPE_MASK: u8 = 0x0f;
const LAT_LON_MASK: u8 = 0x10;
const FEATURE_1_MASK: u8 = 0x20;
const FEATURE_2_MASK: u8 = 0x40;
const NAME_MASK: u8 = 0x80;

/// Structured application data carried by current MeshCore adverts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertData {
    pub node_type: u8,
    pub location_e6: Option<(i32, i32)>,
    pub feature_1: Option<u16>,
    pub feature_2: Option<u16>,
    pub name: Option<String>,
}

impl AdvertData {
    pub fn chat(name: impl Into<String>) -> Self {
        Self {
            node_type: ADVERT_TYPE_CHAT,
            location_e6: None,
            feature_1: None,
            feature_2: None,
            name: Some(name.into()),
        }
    }

    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.node_type > TYPE_MASK {
            return None;
        }
        let mut flags = self.node_type;
        if self.location_e6.is_some() {
            flags |= LAT_LON_MASK;
        }
        if self.feature_1.is_some() {
            flags |= FEATURE_1_MASK;
        }
        if self.feature_2.is_some() {
            flags |= FEATURE_2_MASK;
        }
        if self.name.as_ref().is_some_and(|name| !name.is_empty()) {
            flags |= NAME_MASK;
        }

        let mut out = Vec::with_capacity(MAX_ADVERT_DATA);
        out.push(flags);
        if let Some((latitude, longitude)) = self.location_e6 {
            out.extend_from_slice(&latitude.to_le_bytes());
            out.extend_from_slice(&longitude.to_le_bytes());
        }
        if let Some(feature) = self.feature_1 {
            out.extend_from_slice(&feature.to_le_bytes());
        }
        if let Some(feature) = self.feature_2 {
            out.extend_from_slice(&feature.to_le_bytes());
        }
        if flags & NAME_MASK != 0 {
            out.extend_from_slice(self.name.as_ref()?.as_bytes());
        }
        (out.len() <= MAX_ADVERT_DATA).then_some(out)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ADVERT_DATA {
            return None;
        }
        let flags = bytes[0];
        let mut offset = 1;
        let location_e6 = if flags & LAT_LON_MASK != 0 {
            let latitude = i32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
            offset += 4;
            let longitude = i32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
            offset += 4;
            Some((latitude, longitude))
        } else {
            None
        };
        let feature_1 = if flags & FEATURE_1_MASK != 0 {
            let value = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
            offset += 2;
            Some(value)
        } else {
            None
        };
        let feature_2 = if flags & FEATURE_2_MASK != 0 {
            let value = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
            offset += 2;
            Some(value)
        } else {
            None
        };
        let name = if flags & NAME_MASK != 0 {
            let name = std::str::from_utf8(bytes.get(offset..)?).ok()?;
            (!name.is_empty()).then(|| name.to_owned())
        } else {
            (offset == bytes.len()).then_some(None)?
        };
        Some(Self {
            node_type: flags & TYPE_MASK,
            location_e6,
            feature_1,
            feature_2,
            name,
        })
    }
}

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

    #[test]
    fn current_chat_advert_data_round_trips() {
        let data = AdvertData::chat("Tucket");
        let encoded = data.encode().unwrap();
        assert_eq!(encoded, b"\x81Tucket");
        assert_eq!(AdvertData::decode(&encoded), Some(data));
    }

    #[test]
    fn advert_data_round_trips_optional_fields() {
        let data = AdvertData {
            node_type: ADVERT_TYPE_SENSOR,
            location_e6: Some((40_712_800, -74_006_000)),
            feature_1: Some(7),
            feature_2: Some(9),
            name: Some("weather".into()),
        };
        assert_eq!(AdvertData::decode(&data.encode().unwrap()), Some(data));
    }
}
