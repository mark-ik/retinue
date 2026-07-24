//! The MeshCore symmetric cipher: AES-128 in raw ECB with manual zero padding, wrapped in
//! encrypt-then-MAC by a 2-byte truncated HMAC-SHA256.
//!
//! There is no IV or chaining. Confidentiality rests on every plaintext carrying a unique
//! prefix (a timestamp or tag), so equal plaintexts under the same key would produce equal
//! ciphertext — a property to preserve for interop, not a bug to "fix".
//!
//! Key material is a 32-byte `secret`: either the per-pair ECDH shared secret
//! ([`crate::identity::LocalIdentity::shared_secret`]) or a channel PSK. The AES-128 key is
//! its first 16 bytes; the HMAC key is the full 32 bytes.
//!
//! Blob layout (the "encrypted blob" carried in a packet payload):
//!
//! ```text
//! [ MAC : 2 bytes ] [ ciphertext : ceil(plaintext_len / 16) * 16 bytes ]
//! ```
//!
//! The MAC covers the ciphertext (encrypt-then-MAC). Decryption verifies it in constant time
//! before decrypting, and leaves any trailing zero padding in place (the length is recovered
//! by the payload's own structure, not by unpadding).
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::packet::{CIPHER_KEY_SIZE, CIPHER_MAC_SIZE};

/// AES block size.
const BLOCK: usize = 16;

/// Encrypt `plaintext` under a 32-byte `secret` and prepend the 2-byte MAC.
///
/// Returns `MAC(2) || ciphertext`, where the ciphertext is `plaintext` zero-padded up to a
/// 16-byte multiple and AES-128-ECB encrypted block by block.
pub fn encrypt_then_mac(secret: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(&secret[..CIPHER_KEY_SIZE]));

    let mut ciphertext = plaintext.to_vec();
    let rem = ciphertext.len() % BLOCK;
    if rem != 0 {
        ciphertext.resize(ciphertext.len() + (BLOCK - rem), 0);
    }
    for chunk in ciphertext.chunks_mut(BLOCK) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }

    let mac = mac2(secret, &ciphertext);
    let mut out = Vec::with_capacity(CIPHER_MAC_SIZE + ciphertext.len());
    out.extend_from_slice(&mac);
    out.extend_from_slice(&ciphertext);
    out
}

/// Verify and decrypt `MAC(2) || ciphertext`.
///
/// Returns the decrypted bytes (with any trailing zero padding intact), or `None` if the blob
/// is too short, its ciphertext is not a whole number of blocks, or the MAC does not match.
/// The MAC is checked in constant time before any decryption.
pub fn mac_then_decrypt(secret: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() <= CIPHER_MAC_SIZE {
        return None;
    }
    let (mac, ciphertext) = blob.split_at(CIPHER_MAC_SIZE);
    let expected = mac2(secret, ciphertext);
    if mac.ct_eq(&expected[..]).unwrap_u8() != 1 {
        return None;
    }
    if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
        return None;
    }

    let cipher = Aes128::new(GenericArray::from_slice(&secret[..CIPHER_KEY_SIZE]));
    let mut plaintext = ciphertext.to_vec();
    for chunk in plaintext.chunks_mut(BLOCK) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Some(plaintext)
}

/// The 2-byte MAC: the leftmost [`CIPHER_MAC_SIZE`] bytes of `HMAC-SHA256(secret, ciphertext)`,
/// keyed with the full 32-byte secret.
fn mac2(secret: &[u8; 32], ciphertext: &[u8]) -> [u8; CIPHER_MAC_SIZE] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(ciphertext);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; CIPHER_MAC_SIZE];
    out.copy_from_slice(&full[..CIPHER_MAC_SIZE]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIdentity;

    #[test]
    fn roundtrip_padded_and_unpadded() {
        let secret = [0x5A; 32];
        for msg in [
            &b"one block block!"[..], // exactly 16
            &b"short"[..],
            &b"a message spanning several AES blocks, not a multiple of sixteen"[..],
        ] {
            let blob = encrypt_then_mac(&secret, msg);
            // Blob is MAC(2) + ciphertext, ciphertext a block multiple.
            assert_eq!((blob.len() - CIPHER_MAC_SIZE) % BLOCK, 0);
            let out = mac_then_decrypt(&secret, &blob).expect("verifies and decrypts");
            // Decrypted output is the zero-padded plaintext; the original is a prefix.
            assert!(out.starts_with(msg));
            assert!(out[msg.len()..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn empty_plaintext_yields_an_undecryptable_blob() {
        // An empty plaintext produces a MAC-only 2-byte blob, which decrypt rejects — the same
        // `src_len <= 2` rule MeshCore's MACThenDecrypt applies. Real payloads always carry at
        // least a timestamp prefix, so this case does not arise in practice.
        let secret = [0x5A; 32];
        let blob = encrypt_then_mac(&secret, b"");
        assert_eq!(blob.len(), CIPHER_MAC_SIZE);
        assert!(mac_then_decrypt(&secret, &blob).is_none());
    }

    #[test]
    fn wrong_key_is_rejected_by_mac() {
        let blob = encrypt_then_mac(&[1u8; 32], b"secret payload");
        assert!(mac_then_decrypt(&[2u8; 32], &blob).is_none());
    }

    #[test]
    fn a_flipped_ciphertext_byte_fails_the_mac() {
        let secret = [0x11; 32];
        let mut blob = encrypt_then_mac(&secret, b"tamper me please, sir");
        let last = blob.len() - 1;
        blob[last] ^= 0x80;
        assert!(mac_then_decrypt(&secret, &blob).is_none());
    }

    #[test]
    fn too_short_blob_is_rejected() {
        assert!(mac_then_decrypt(&[0; 32], &[]).is_none());
        assert!(mac_then_decrypt(&[0; 32], &[0x00, 0x11]).is_none()); // MAC only, no ct
    }

    #[test]
    fn ecdh_is_symmetric() {
        // Two parties derive the same per-pair secret from each other's public key.
        let alice = LocalIdentity::from_seed([0x01; 32]);
        let bob = LocalIdentity::from_seed([0x02; 32]);
        let ab = alice.shared_secret(&bob.identity()).unwrap();
        let ba = bob.shared_secret(&alice.identity()).unwrap();
        assert_eq!(ab, ba, "X25519 ECDH is symmetric");
        assert_ne!(ab, [0u8; 32], "and not degenerate");
    }

    #[test]
    fn ecdh_secret_actually_encrypts() {
        // A full round trip over the pairwise ECDH secret, the way TXT_MSG uses it.
        let alice = LocalIdentity::from_seed([0x0A; 32]);
        let bob = LocalIdentity::from_seed([0x0B; 32]);
        let secret = alice.shared_secret(&bob.identity()).unwrap();
        let blob = encrypt_then_mac(&secret, b"hello from alice");
        let back = bob.shared_secret(&alice.identity()).unwrap();
        let out = mac_then_decrypt(&back, &blob).unwrap();
        assert!(out.starts_with(b"hello from alice"));
    }
}
