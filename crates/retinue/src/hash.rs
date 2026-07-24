//! Hashes and their truncations.
//!
//! Every hash in Reticulum is SHA-256, and every short form is a *prefix truncation* of
//! it. There are three lengths in play, and using the wrong one is a silent
//! wire-incompatibility bug, so each has its own type rather than being a bare `[u8; N]`.
//!
//! | length | used for |
//! |---|---|
//! | 32 | the full digest, and the input to the truncated forms |
//! | 16 | address hashes: identity hashes, destination hashes, link ids |
//! | 10 | name hashes and ratchet ids |
//!
//! Verified against RNS 1.3.8: `Identity.TRUNCATED_HASHLENGTH = 128` bits and
//! `Identity.NAME_HASH_LENGTH = 80` bits.

use core::fmt;

use sha2::{Digest, Sha256};

/// Length of a full SHA-256 digest.
pub const HASH_LEN: usize = 32;

/// Length of an address hash: identity hashes, destination hashes, link ids.
pub const ADDRESS_HASH_LEN: usize = 16;

/// Length of a name hash, and of a ratchet id.
pub const NAME_HASH_LEN: usize = 10;

/// The full SHA-256 of `data`.
pub fn full_hash(data: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(data).into()
}

/// A 16-byte address hash: an identity, a destination, or a link.
///
/// Always `full_hash(..)[..16]`. The type exists to stop a name hash being passed where an
/// address hash is wanted, which the wire would accept and then quietly reject.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AddressHash([u8; ADDRESS_HASH_LEN]);

impl AddressHash {
    /// Wrap 16 bytes that are already an address hash.
    pub const fn from_bytes(bytes: [u8; ADDRESS_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Hash `data` and truncate to 16 bytes.
    pub fn of(data: &[u8]) -> Self {
        let mut out = [0u8; ADDRESS_HASH_LEN];
        out.copy_from_slice(&full_hash(data)[..ADDRESS_HASH_LEN]);
        Self(out)
    }

    /// Read an address hash from the front of `slice`, if it is long enough.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let bytes: [u8; ADDRESS_HASH_LEN] = slice.get(..ADDRESS_HASH_LEN)?.try_into().ok()?;
        Some(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; ADDRESS_HASH_LEN] {
        &self.0
    }

    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AddressHash({self})")
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A 10-byte name hash, or a ratchet id.
///
/// The trap this type exists to prevent: a name hash is the *first ten bytes* of the
/// SHA-256 of the expanded name. Matching on the full 32-byte digest, or on a zero-padded
/// 32-byte buffer, silently never matches anything on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameHash([u8; NAME_HASH_LEN]);

impl NameHash {
    pub const fn from_bytes(bytes: [u8; NAME_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Hash `data` and truncate to 10 bytes.
    pub fn of(data: &[u8]) -> Self {
        let mut out = [0u8; NAME_HASH_LEN];
        out.copy_from_slice(&full_hash(data)[..NAME_HASH_LEN]);
        Self(out)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        let bytes: [u8; NAME_HASH_LEN] = slice.get(..NAME_HASH_LEN)?.try_into().ok()?;
        Some(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; NAME_HASH_LEN] {
        &self.0
    }

    pub const fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for NameHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameHash({self})")
    }
}

impl fmt::Display for NameHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncations_are_prefixes_of_the_full_digest() {
        let data = b"retinue";
        let full = full_hash(data);
        assert_eq!(AddressHash::of(data).as_slice(), &full[..ADDRESS_HASH_LEN]);
        assert_eq!(NameHash::of(data).as_slice(), &full[..NAME_HASH_LEN]);
    }
}
