//! MeshCore identities: Ed25519 keys, node hashes, signing.
//!
//! A node's mesh hash is simply a prefix of its public key (1 byte at the
//! current path-hash size), so hash collision handling is a protocol fact of
//! life, not an error. Signatures are standard Ed25519 (RFC 8032), wire
//! compatible with upstream's C implementation.
//!
//! Ported from upstream MeshCore (MIT, <https://github.com/ripplebiz/MeshCore>).

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::packet::{PUB_KEY_SIZE, SIGNATURE_SIZE};

/// Current path-hash size (bytes of pub key prefix used as the node hash).
pub const PATH_HASH_SIZE: usize = 1;

/// A remote party: public key only, signatures can be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub pub_key: [u8; PUB_KEY_SIZE],
}

impl Identity {
    pub fn new(pub_key: [u8; PUB_KEY_SIZE]) -> Self {
        Identity { pub_key }
    }

    /// The node hash: a prefix of the public key.
    pub fn hash(&self) -> [u8; PATH_HASH_SIZE] {
        let mut h = [0u8; PATH_HASH_SIZE];
        h.copy_from_slice(&self.pub_key[..PATH_HASH_SIZE]);
        h
    }

    pub fn hash_matches(&self, hash: &[u8]) -> bool {
        hash.len() <= PUB_KEY_SIZE && self.pub_key[..hash.len()] == *hash
    }

    /// Ed25519 signature verification. False for malformed keys or sigs.
    pub fn verify(&self, sig: &[u8], message: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.pub_key) else {
            return false;
        };
        let Ok(sig): Result<[u8; SIGNATURE_SIZE], _> = sig.try_into() else {
            return false;
        };
        key.verify(message, &Signature::from_bytes(&sig)).is_ok()
    }
}

/// A local party: keypair on this device, can sign and derive shared secrets.
pub struct LocalIdentity {
    signing: SigningKey,
    /// The X25519 scalar for ECDH: the clamped `SHA512(seed)[0..32]`, the same value MeshCore
    /// stores as the first half of its expanded 64-byte private key.
    x25519_scalar: [u8; 32],
}

impl LocalIdentity {
    /// Build from a 32-byte Ed25519 seed (the caller owns seed generation
    /// and storage; this crate takes no dependency on an RNG).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        // The Ed25519 secret scalar is the clamped first half of SHA512(seed); this is what
        // MeshCore keeps as prv_key[0..32] and feeds to X25519 for ECDH.
        let hash = Sha512::digest(seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        LocalIdentity {
            signing: SigningKey::from_bytes(&seed),
            x25519_scalar: scalar,
        }
    }

    pub fn identity(&self) -> Identity {
        Identity::new(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        self.signing.sign(message).to_bytes()
    }

    /// The MeshCore ECDH shared secret with `peer`: X25519 Diffie-Hellman over the Ed25519
    /// keys transposed to Montgomery form (`u = (1 + y) / (1 - y)`), matching upstream's
    /// `ed25519_key_exchange`. Returns `None` if the peer's key is not a valid curve point.
    /// The 32-byte result is the key material for the per-pair cipher (see [`crate::cipher`]).
    pub fn shared_secret(&self, peer: &Identity) -> Option<[u8; 32]> {
        let montgomery = CompressedEdwardsY(peer.pub_key).decompress()?.to_montgomery();
        Some(montgomery.mul_clamped(self.x25519_scalar).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let li = LocalIdentity::from_seed([7u8; 32]);
        let id = li.identity();
        let sig = li.sign(b"advert body");
        assert!(id.verify(&sig, b"advert body"));
        assert!(!id.verify(&sig, b"advert bodY"));
    }

    #[test]
    fn hash_is_pub_key_prefix() {
        let li = LocalIdentity::from_seed([9u8; 32]);
        let id = li.identity();
        assert_eq!(id.hash()[0], id.pub_key[0]);
        assert!(id.hash_matches(&id.hash()));
    }

    #[test]
    fn bad_sig_len_rejected() {
        let li = LocalIdentity::from_seed([1u8; 32]);
        let id = li.identity();
        assert!(!id.verify(&[0u8; 63], b"m"));
    }
}
