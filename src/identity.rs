//! Dual-key identities.
//!
//! A Reticulum identity is two keypairs: X25519 for ECDH and Ed25519 for signing. On the
//! wire the public form is always the two public keys concatenated, X25519 first:
//!
//! ```text
//! public  = x25519_public(32)  || ed25519_verifying(32)   = 64 bytes
//! private = x25519_secret(32)  || ed25519_seed(32)        = 64 bytes
//! ```
//!
//! The identity hash is `trunc16(SHA256(public))`, and it doubles as the HKDF salt for
//! encryption to this identity. Both facts are verified against RNS 1.3.8; see
//! `tests/fixtures/manifest.json`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::hash::AddressHash;
use crate::{Error, Result};

/// Length of one key, public or secret. Both curves use 32 bytes.
pub const KEY_LEN: usize = 32;

/// Length of a full public or private identity: two keys.
pub const IDENTITY_LEN: usize = KEY_LEN * 2;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A peer's public identity: the two public keys, and the hash they imply.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    x25519: XPublicKey,
    ed25519: VerifyingKey,
    hash: AddressHash,
}

impl Identity {
    /// Build an identity from its two public keys.
    pub fn new(x25519: XPublicKey, ed25519: VerifyingKey) -> Self {
        let mut buf = [0u8; IDENTITY_LEN];
        buf[..KEY_LEN].copy_from_slice(x25519.as_bytes());
        buf[KEY_LEN..].copy_from_slice(ed25519.as_bytes());
        let hash = AddressHash::of(&buf);
        Self {
            x25519,
            ed25519,
            hash,
        }
    }

    /// Parse the 64-byte wire form: `x25519_public(32) || ed25519_verifying(32)`.
    ///
    /// Fails if the Ed25519 half is not a valid point.
    pub fn from_public_bytes(bytes: &[u8; IDENTITY_LEN]) -> Result<Self> {
        let x: [u8; KEY_LEN] = bytes[..KEY_LEN].try_into().expect("half of 64 is 32");
        let e: [u8; KEY_LEN] = bytes[KEY_LEN..].try_into().expect("half of 64 is 32");
        let ed25519 = VerifyingKey::from_bytes(&e).map_err(|_| Error::BadKey)?;
        Ok(Self::new(XPublicKey::from(x), ed25519))
    }

    /// The 64-byte wire form.
    pub fn to_public_bytes(&self) -> [u8; IDENTITY_LEN] {
        let mut out = [0u8; IDENTITY_LEN];
        out[..KEY_LEN].copy_from_slice(self.x25519.as_bytes());
        out[KEY_LEN..].copy_from_slice(self.ed25519.as_bytes());
        out
    }

    /// The X25519 public key: the ECDH half.
    pub fn x25519_bytes(&self) -> &[u8; KEY_LEN] {
        self.x25519.as_bytes()
    }

    /// The Ed25519 verifying key: the signing half.
    pub fn ed25519_bytes(&self) -> &[u8; KEY_LEN] {
        self.ed25519.as_bytes()
    }

    pub(crate) fn x25519(&self) -> &XPublicKey {
        &self.x25519
    }

    /// `trunc16(SHA256(public))`. Also the HKDF salt for encrypting to this identity.
    pub fn hash(&self) -> AddressHash {
        self.hash
    }

    /// Verify an Ed25519 signature over `message`.
    ///
    /// Uses strict verification, which rejects small-order and non-canonical points. RNS
    /// signatures pass it; see the `announce_*` fixtures.
    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.ed25519.verify_strict(message, &sig).is_ok()
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({})", self.hash)
    }
}

/// A local identity, holding both secret keys.
#[derive(Clone)]
pub struct PrivateIdentity {
    x25519: StaticSecret,
    ed25519: SigningKey,
    public: Identity,
}

impl PrivateIdentity {
    /// Build from the 64-byte private form: `x25519_secret(32) || ed25519_seed(32)`.
    ///
    /// This byte order is not a convention we chose; it is what RNS reads and writes, and
    /// the fixture vector pins it.
    pub fn from_secret_bytes(bytes: &[u8; IDENTITY_LEN]) -> Self {
        let x: [u8; KEY_LEN] = bytes[..KEY_LEN].try_into().expect("half of 64 is 32");
        let e: [u8; KEY_LEN] = bytes[KEY_LEN..].try_into().expect("half of 64 is 32");

        let x25519 = StaticSecret::from(x);
        let ed25519 = SigningKey::from_bytes(&e);
        let public = Identity::new(XPublicKey::from(&x25519), ed25519.verifying_key());

        Self {
            x25519,
            ed25519,
            public,
        }
    }

    /// The 64-byte private form.
    pub fn to_secret_bytes(&self) -> [u8; IDENTITY_LEN] {
        let mut out = [0u8; IDENTITY_LEN];
        out[..KEY_LEN].copy_from_slice(&self.x25519.to_bytes());
        out[KEY_LEN..].copy_from_slice(self.ed25519.as_bytes());
        out
    }

    /// The public half.
    pub fn public(&self) -> &Identity {
        &self.public
    }

    /// Shorthand for `self.public().hash()`.
    pub fn hash(&self) -> AddressHash {
        self.public.hash
    }

    /// Sign a message with the Ed25519 half.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.ed25519.sign(message).to_bytes()
    }

    /// X25519 ECDH against a peer's public key.
    pub(crate) fn diffie_hellman(&self, peer: &XPublicKey) -> [u8; KEY_LEN] {
        self.x25519.diffie_hellman(peer).to_bytes()
    }
}

impl core::fmt::Debug for PrivateIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateIdentity({})", self.public.hash)
    }
}
