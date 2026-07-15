//! The encrypted token.
//!
//! Reticulum's token is derived from Fernet but is deliberately not Fernet: the version
//! byte and the 8-byte timestamp are stripped, because they cost bytes and leak initiator
//! metadata. What remains is:
//!
//! ```text
//! token = IV(16) || AES-256-CBC(PKCS7(plaintext)) || HMAC-SHA256(32)
//! ```
//!
//! with the HMAC covering `IV || ciphertext`.
//!
//! When encrypting *to an identity* (rather than over an established link) an ephemeral
//! X25519 public key is prepended, giving the full on-wire form:
//!
//! ```text
//! ephemeral_x25519_pub(32) || IV(16) || ciphertext || HMAC-SHA256(32)
//! ```
//!
//! Note the ephemeral key is **not** covered by the HMAC.
//!
//! Keys come from:
//!
//! ```text
//! derived  = HKDF-SHA256(ikm = x25519_shared, salt = identity_hash(16), info = <empty>, len = 64)
//! sign_key = derived[0..32]     (HMAC-SHA256)
//! enc_key  = derived[32..64]    (AES-256)
//! ```
//!
//! Every line of this was settled by decrypting a real RNS 1.3.8 token: all four
//! combinations of {AES-128, AES-256} x {sign-key-first, enc-key-first} were tried, and
//! only AES-256 with the signing key first both authenticates and decrypts. The Beechat
//! crate gets this right on one code path and wrong on another, so it could not be trusted
//! here.

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::PublicKey as XPublicKey;

use crate::hash::AddressHash;
use crate::identity::{Identity, KEY_LEN, PrivateIdentity};
use crate::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Length of the AES-CBC initialisation vector.
pub const IV_LEN: usize = 16;

/// Length of the HMAC-SHA256 tag.
pub const MAC_LEN: usize = 32;

/// Bytes a token adds on top of the padded plaintext: `IV + HMAC`.
///
/// RNS calls this `TOKEN_OVERHEAD` and reports 48, which agrees.
pub const TOKEN_OVERHEAD: usize = IV_LEN + MAC_LEN;

/// Total bytes the HKDF produces, split evenly into signing and encryption keys.
pub const DERIVED_KEY_LEN: usize = 64;

/// The two symmetric keys for a token.
#[derive(Clone)]
pub struct DerivedKeys {
    sign: [u8; 32],
    enc: [u8; 32],
}

impl DerivedKeys {
    /// Stretch an X25519 shared secret into the signing and encryption keys.
    ///
    /// The salt is the recipient's identity hash. The info string is empty.
    pub fn derive(shared_secret: &[u8; KEY_LEN], salt: AddressHash) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), shared_secret);
        let mut okm = [0u8; DERIVED_KEY_LEN];
        hk.expand(&[], &mut okm)
            .expect("64 bytes is a valid HKDF-SHA256 output length");

        let mut sign = [0u8; 32];
        let mut enc = [0u8; 32];
        sign.copy_from_slice(&okm[..32]);
        enc.copy_from_slice(&okm[32..]);
        Self { sign, enc }
    }

    /// Encrypt, producing `IV || ciphertext || HMAC`.
    ///
    /// `iv` is supplied by the caller so this stays free of any RNG and reproducible in
    /// tests. It must be fresh and unpredictable in production.
    pub fn encrypt(&self, plaintext: &[u8], iv: &[u8; IV_LEN]) -> Vec<u8> {
        let cipher = Aes256CbcEnc::new(&self.enc.into(), iv.into());

        let mut out = Vec::with_capacity(IV_LEN + plaintext.len() + 16 + MAC_LEN);
        out.extend_from_slice(iv);

        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct = cipher
            .encrypt_padded_b2b::<Pkcs7>(plaintext, &mut buf)
            .expect("buffer has a full block of headroom");
        out.extend_from_slice(ct);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.sign)
            .expect("HMAC accepts a 32-byte key");
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }

    /// Verify and decrypt `IV || ciphertext || HMAC`.
    ///
    /// The HMAC is checked before anything is decrypted, and in constant time.
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>> {
        if token.len() <= TOKEN_OVERHEAD {
            return Err(Error::Truncated);
        }
        let (body, tag) = token.split_at(token.len() - MAC_LEN);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.sign)
            .expect("HMAC accepts a 32-byte key");
        mac.update(body);
        mac.verify_slice(tag).map_err(|_| Error::BadMac)?;

        let (iv, ciphertext) = body.split_at(IV_LEN);
        let iv: [u8; IV_LEN] = iv.try_into().expect("split at IV_LEN");
        if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
            return Err(Error::BadPadding);
        }

        let cipher = Aes256CbcDec::new(&self.enc.into(), (&iv).into());
        let mut buf = vec![0u8; ciphertext.len()];
        let pt = cipher
            .decrypt_padded_b2b::<Pkcs7>(ciphertext, &mut buf)
            .map_err(|_| Error::BadPadding)?;
        Ok(pt.to_vec())
    }
}

/// Decrypt a token addressed to us: `ephemeral_pub(32) || IV || ciphertext || HMAC`.
///
/// The ephemeral public key is read off the front, ECDH'd against our X25519 secret, and
/// the result stretched with our own identity hash as the salt.
pub fn decrypt_to_identity(recipient: &PrivateIdentity, token: &[u8]) -> Result<Vec<u8>> {
    if token.len() < KEY_LEN + TOKEN_OVERHEAD {
        return Err(Error::Truncated);
    }
    let eph: [u8; KEY_LEN] = token[..KEY_LEN].try_into().expect("checked length");
    let shared = recipient.diffie_hellman(&XPublicKey::from(eph));
    let keys = DerivedKeys::derive(&shared, recipient.hash());
    keys.decrypt(&token[KEY_LEN..])
}

/// Encrypt a token to a peer identity, given a caller-supplied ephemeral secret and IV.
///
/// Both are parameters rather than generated here so this module needs no RNG and stays
/// reproducible. In production the runtime layer must supply a fresh, unpredictable
/// ephemeral secret for every single token: reuse destroys the security of the scheme.
pub fn encrypt_to_identity(
    recipient: &Identity,
    ephemeral_secret: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let secret = x25519_dalek::StaticSecret::from(*ephemeral_secret);
    let eph_public = XPublicKey::from(&secret);
    let shared = secret.diffie_hellman(recipient.x25519()).to_bytes();

    // Salt is the *recipient's* identity hash: the sender must know who it is talking to.
    let keys = DerivedKeys::derive(&shared, recipient.hash());

    let mut out = Vec::new();
    out.extend_from_slice(eph_public.as_bytes());
    out.extend_from_slice(&keys.encrypt(plaintext, iv));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_our_own_code() {
        let recipient = PrivateIdentity::from_secret_bytes(&[7u8; 64]);
        let token = encrypt_to_identity(
            recipient.public(),
            &[9u8; 32],
            &[3u8; IV_LEN],
            b"hello retinue",
        );
        let back = decrypt_to_identity(&recipient, &token).unwrap();
        assert_eq!(back, b"hello retinue");
    }

    #[test]
    fn a_flipped_ciphertext_byte_fails_the_mac() {
        let recipient = PrivateIdentity::from_secret_bytes(&[7u8; 64]);
        let mut token = encrypt_to_identity(
            recipient.public(),
            &[9u8; 32],
            &[3u8; IV_LEN],
            b"hello retinue",
        );
        let n = token.len();
        token[n - MAC_LEN - 1] ^= 0xFF;
        assert!(matches!(
            decrypt_to_identity(&recipient, &token),
            Err(Error::BadMac)
        ));
    }
}
