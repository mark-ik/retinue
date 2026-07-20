//! Encrypted message payloads: text messages, acks, and channel (group) text.
//!
//! Each carries a small cleartext prefix (1-byte destination/source/channel hashes and the
//! 2-byte MAC) followed by the encrypted blob from [`crate::cipher`]. A text message and a
//! request use the per-pair ECDH secret; channel text uses the channel pre-shared key.
//!
//! Plaintext layouts (inside the encrypted blob), all timestamps `u32` little-endian:
//!
//! ```text
//! TXT_MSG   timestamp(4) || ctrl(1) || text            ctrl = (attempt & 0x03) | (txt_type << 2)
//! GRP_TXT   timestamp(4) || ctrl(1)=0 || "name: msg"
//! ```
//!
//! An ACK is unencrypted: `ack_crc(4)`, the leftmost 4 bytes of
//! `SHA256(timestamp(4) || ctrl(1) || text || sender_pub_key(32))`, which both sides compute
//! from the message so a receiver's ack matches without carrying the text back.
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use sha2::{Digest, Sha256};

use crate::cipher::{encrypt_then_mac, mac_then_decrypt};
use crate::packet::PUB_KEY_SIZE;

/// Plain UTF-8 text.
pub const TXT_TYPE_PLAIN: u8 = 0;
/// CLI command data.
pub const TXT_TYPE_CLI_DATA: u8 = 1;
/// Signed plain text (the ack hash then covers the receiver's key instead).
pub const TXT_TYPE_SIGNED_PLAIN: u8 = 2;

/// A decrypted text message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMessage {
    /// Sender's clock at composition, seconds.
    pub timestamp: u32,
    /// Send attempt, 0..=3 (the low two bits of the control byte).
    pub attempt: u8,
    /// One of the `TXT_TYPE_*` values.
    pub txt_type: u8,
    pub text: String,
}

impl TextMessage {
    /// A fresh plain text message.
    pub fn plain(timestamp: u32, text: impl Into<String>) -> Self {
        TextMessage {
            timestamp,
            attempt: 0,
            txt_type: TXT_TYPE_PLAIN,
            text: text.into(),
        }
    }

    fn ctrl(&self) -> u8 {
        (self.attempt & 0x03) | (self.txt_type << 2)
    }

    /// The plaintext that goes inside the encrypted blob: `timestamp(4 LE) || ctrl(1) || text`.
    fn plaintext(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(5 + self.text.len());
        p.extend_from_slice(&self.timestamp.to_le_bytes());
        p.push(self.ctrl());
        p.extend_from_slice(self.text.as_bytes());
        p
    }

    fn from_plaintext(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let timestamp = u32::from_le_bytes(bytes[..4].try_into().ok()?);
        let ctrl = bytes[4];
        // The cipher leaves zero padding on the tail; text runs to the first NUL or end.
        let tail = &bytes[5..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let text = String::from_utf8(tail[..end].to_vec()).ok()?;
        Some(TextMessage {
            timestamp,
            attempt: ctrl & 0x03,
            txt_type: ctrl >> 2,
            text,
        })
    }

    /// Encode a TXT_MSG packet payload: `dest_hash(1) || src_hash(1) || MAC(2) || ciphertext`,
    /// encrypted under the per-pair `secret`.
    pub fn encode(&self, secret: &[u8; 32], dest_hash: u8, src_hash: u8) -> Vec<u8> {
        let blob = encrypt_then_mac(secret, &self.plaintext());
        let mut out = Vec::with_capacity(2 + blob.len());
        out.push(dest_hash);
        out.push(src_hash);
        out.extend_from_slice(&blob);
        out
    }

    /// Decode a TXT_MSG packet payload with the per-pair `secret`, returning the cleartext
    /// `(dest_hash, src_hash)` prefix and the message. `None` if too short or the MAC fails.
    pub fn decode(payload: &[u8], secret: &[u8; 32]) -> Option<(u8, u8, TextMessage)> {
        if payload.len() < 2 {
            return None;
        }
        let dest_hash = payload[0];
        let src_hash = payload[1];
        let plaintext = mac_then_decrypt(secret, &payload[2..])?;
        let msg = TextMessage::from_plaintext(&plaintext)?;
        Some((dest_hash, src_hash, msg))
    }

    /// The 4-byte ack value for this message: the leftmost 4 bytes of
    /// `SHA256(timestamp(4) || ctrl(1) || text || sender_pub_key(32))`. Both ends compute it,
    /// so a receiver's ACK matches the sender's expectation without echoing the text.
    pub fn ack_crc(&self, sender_pub_key: &[u8; PUB_KEY_SIZE]) -> [u8; 4] {
        let mut h = Sha256::new();
        h.update(self.timestamp.to_le_bytes());
        h.update([self.ctrl()]);
        h.update(self.text.as_bytes());
        h.update(sender_pub_key);
        let full = h.finalize();
        let mut out = [0u8; 4];
        out.copy_from_slice(&full[..4]);
        out
    }
}

/// An ACK packet payload: just the 4-byte ack value, unencrypted.
pub fn encode_ack(ack_crc: [u8; 4]) -> Vec<u8> {
    ack_crc.to_vec()
}

/// The ack value from an ACK packet payload (its first 4 bytes; any trailing attempt/random
/// bytes are ignored, and only the first 4 are matched, as upstream does).
pub fn decode_ack(payload: &[u8]) -> Option<[u8; 4]> {
    payload.get(..4)?.try_into().ok()
}

/// A channel's 1-byte hash: the first byte of `SHA256(psk)`.
pub fn channel_hash(psk: &[u8]) -> u8 {
    Sha256::digest(psk)[0]
}

/// A decrypted channel (group) text message. The body is the upstream `"<name>: <msg>"`
/// string; sender attribution is unauthenticated on a shared channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupText {
    pub timestamp: u32,
    pub body: String,
}

impl GroupText {
    pub fn new(timestamp: u32, body: impl Into<String>) -> Self {
        GroupText {
            timestamp,
            body: body.into(),
        }
    }

    fn plaintext(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(5 + self.body.len());
        p.extend_from_slice(&self.timestamp.to_le_bytes());
        p.push(0); // ctrl = TXT_TYPE_PLAIN
        p.extend_from_slice(self.body.as_bytes());
        p
    }

    /// Encode a GRP_TXT payload: `channel_hash(1) || MAC(2) || ciphertext`, encrypted under the
    /// 32-byte channel PSK.
    pub fn encode(&self, psk: &[u8; 32]) -> Vec<u8> {
        let blob = encrypt_then_mac(psk, &self.plaintext());
        let mut out = Vec::with_capacity(1 + blob.len());
        out.push(channel_hash(psk));
        out.extend_from_slice(&blob);
        out
    }

    /// Decode a GRP_TXT payload with the channel PSK. `None` if too short, the channel hash
    /// mismatches, the MAC fails, or the control byte is not plain text.
    pub fn decode(payload: &[u8], psk: &[u8; 32]) -> Option<GroupText> {
        let (&ch, rest) = payload.split_first()?;
        if ch != channel_hash(psk) {
            return None;
        }
        let plaintext = mac_then_decrypt(psk, rest)?;
        if plaintext.len() < 5 || plaintext[4] >> 2 != TXT_TYPE_PLAIN {
            return None;
        }
        let timestamp = u32::from_le_bytes(plaintext[..4].try_into().ok()?);
        let tail = &plaintext[5..];
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        let body = String::from_utf8(tail[..end].to_vec()).ok()?;
        Some(GroupText { timestamp, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    #[test]
    fn text_message_round_trips_over_the_pairwise_secret() {
        let alice = LocalIdentity::from_seed([0x1A; 32]);
        let bob = LocalIdentity::from_seed([0x1B; 32]);
        let secret = alice.shared_secret(&bob.identity()).unwrap();

        let msg = TextMessage::plain(1_752_969_600, "meet at the repeater");
        let dest = bob.identity().hash()[0];
        let src = alice.identity().hash()[0];
        let payload = msg.encode(&secret, dest, src);

        let back = bob.shared_secret(&alice.identity()).unwrap();
        let (d, s, got) = TextMessage::decode(&payload, &back).unwrap();
        assert_eq!((d, s), (dest, src));
        assert_eq!(got, msg);
    }

    #[test]
    fn wrong_secret_fails_the_mac() {
        let secret = [0x22; 32];
        let payload = TextMessage::plain(5, "hi").encode(&secret, 1, 2);
        assert!(TextMessage::decode(&payload, &[0x33; 32]).is_none());
    }

    #[test]
    fn ack_crc_matches_on_both_sides() {
        // The sender's expected ack and a receiver recomputing from the decoded message agree.
        let alice = LocalIdentity::from_seed([0x2A; 32]);
        let bob = LocalIdentity::from_seed([0x2B; 32]);
        let secret = alice.shared_secret(&bob.identity()).unwrap();
        let msg = TextMessage::plain(99, "ping");
        let sender_pub = alice.identity().pub_key;

        let payload = msg.encode(&secret, bob.identity().hash()[0], alice.identity().hash()[0]);
        let (_, _, recv) = TextMessage::decode(&payload, &secret).unwrap();

        let sender_ack = msg.ack_crc(&sender_pub);
        let receiver_ack = recv.ack_crc(&sender_pub);
        assert_eq!(sender_ack, receiver_ack);
        assert_eq!(decode_ack(&encode_ack(sender_ack)), Some(sender_ack));
    }

    #[test]
    fn attempt_and_type_survive_the_ctrl_byte() {
        let secret = [0x44; 32];
        let mut msg = TextMessage::plain(7, "retry me");
        msg.attempt = 2;
        msg.txt_type = TXT_TYPE_CLI_DATA;
        let payload = msg.encode(&secret, 9, 8);
        let (_, _, got) = TextMessage::decode(&payload, &secret).unwrap();
        assert_eq!(got.attempt, 2);
        assert_eq!(got.txt_type, TXT_TYPE_CLI_DATA);
        assert_eq!(got.text, "retry me");
    }

    #[test]
    fn group_text_round_trips_over_the_psk() {
        let psk = [0x5A; 32];
        let gt = GroupText::new(1000, "alice: hello channel");
        let payload = gt.encode(&psk);
        assert_eq!(payload[0], channel_hash(&psk));
        assert_eq!(GroupText::decode(&payload, &psk), Some(gt));
    }

    #[test]
    fn group_text_rejects_a_foreign_channel() {
        let payload = GroupText::new(1, "x: y").encode(&[0x01; 32]);
        assert!(GroupText::decode(&payload, &[0x02; 32]).is_none());
    }
}
