//! Authenticated MeshCore PATH payloads used to establish reciprocal direct routes.
//!
//! The outer packet uses the ordinary pairwise datagram prefix. Inside the encrypted blob:
//! `path_len || path || extra_type || extra`. A PATH received by flood carries the path the
//! peer should use to return directly; the receiver answers with its reciprocal path.

use crate::cipher::{encrypt_then_mac, mac_then_decrypt};
use crate::packet::{MAX_PAYLOAD, Packet};

/// A decoded direct route and optional piggy-backed response such as an ACK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathMessage {
    pub path_len: u8,
    pub path: Vec<u8>,
    pub extra_type: u8,
    pub extra: Vec<u8>,
}

impl PathMessage {
    /// Build a V1 path message. Returns `None` when the packed path is malformed.
    pub fn new(path_len: u8, path: &[u8], extra_type: u8, extra: &[u8]) -> Option<Self> {
        if !Packet::is_valid_path_len(path_len) {
            return None;
        }
        let byte_len = ((path_len >> 6) as usize + 1) * (path_len & 63) as usize;
        if path.len() != byte_len {
            return None;
        }
        Some(Self {
            path_len,
            path: path.to_vec(),
            extra_type: extra_type & 0x0f,
            extra: extra.to_vec(),
        })
    }

    /// Encode the pairwise PATH payload: clear destination/source hashes followed by the
    /// authenticated encrypted route.
    pub fn encode(&self, secret: &[u8; 32], dest_hash: u8, src_hash: u8) -> Option<Vec<u8>> {
        let mut plain = Vec::with_capacity(2 + self.path.len() + self.extra.len());
        plain.push(self.path_len);
        plain.extend_from_slice(&self.path);
        plain.push(self.extra_type);
        plain.extend_from_slice(&self.extra);
        let blob = encrypt_then_mac(secret, &plain);
        let mut payload = Vec::with_capacity(2 + blob.len());
        payload.push(dest_hash);
        payload.push(src_hash);
        payload.extend_from_slice(&blob);
        (payload.len() <= MAX_PAYLOAD).then_some(payload)
    }

    /// Decrypt and validate a pairwise PATH payload.
    pub fn decode(payload: &[u8], secret: &[u8; 32]) -> Option<(u8, u8, Self)> {
        let (&dest_hash, rest) = payload.split_first()?;
        let (&src_hash, blob) = rest.split_first()?;
        let plain = mac_then_decrypt(secret, blob)?;
        let &path_len = plain.first()?;
        if !Packet::is_valid_path_len(path_len) {
            return None;
        }
        let path_bytes = ((path_len >> 6) as usize + 1) * (path_len & 63) as usize;
        let extra_type_at = 1 + path_bytes;
        let path = plain.get(1..extra_type_at)?.to_vec();
        let extra_type = *plain.get(extra_type_at)? & 0x0f;
        let extra = plain.get(extra_type_at + 1..)?.to_vec();
        Some((
            dest_hash,
            src_hash,
            Self {
                path_len,
                path,
                extra_type,
                extra,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::payload_type;

    #[test]
    fn authenticated_path_round_trips() {
        let route =
            PathMessage::new(3, &[0x11, 0x22, 0x33], payload_type::ACK, &[1, 2, 3, 4]).unwrap();
        let encoded = route.encode(&[0x55; 32], 0xaa, 0xbb).unwrap();
        let (dest, src, decoded) = PathMessage::decode(&encoded, &[0x55; 32]).unwrap();
        assert_eq!((dest, src), (0xaa, 0xbb));
        assert_eq!(decoded.path_len, route.path_len);
        assert_eq!(decoded.path, route.path);
        assert_eq!(decoded.extra_type, payload_type::ACK);
        assert!(decoded.extra.starts_with(&[1, 2, 3, 4]));
    }

    #[test]
    fn malformed_path_is_rejected() {
        assert!(PathMessage::new(2, &[0x11], 0, &[]).is_none());
    }
}
