//! Destination names and their hashes.
//!
//! A destination is named by an app name and a list of aspects. They join with `.` into an
//! *expanded name*, e.g. `("retinue", ["test"])` becomes `retinue.test`. Two hashes fall
//! out of it, and they are not interchangeable:
//!
//! ```text
//! name_hash        = trunc10(SHA256(expanded_name))
//! destination_hash = trunc16(SHA256(name_hash || identity_hash))
//! ```
//!
//! Note the second is a hash of two hashes, and that the identity participates only
//! through its own hash. Verified against RNS 1.3.8: the fixture vector reproduces
//! `example_utilities.announcesample.fruits` as `2419dca3c93718497b91990373df1503`.

use crate::hash::{AddressHash, NameHash};
use crate::identity::Identity;

/// The name of a destination: an app name plus dotted aspects.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DestinationName {
    expanded: String,
    name_hash: NameHash,
}

impl DestinationName {
    /// Build from an app name and aspects. They are joined with `.`.
    ///
    /// `DestinationName::new("retinue", ["test"])` expands to `retinue.test`.
    pub fn new<I, S>(app_name: &str, aspects: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut expanded = String::from(app_name);
        for aspect in aspects {
            expanded.push('.');
            expanded.push_str(aspect.as_ref());
        }
        let name_hash = NameHash::of(expanded.as_bytes());
        Self {
            expanded,
            name_hash,
        }
    }

    /// The dotted name, e.g. `retinue.test`.
    pub fn expanded(&self) -> &str {
        &self.expanded
    }

    /// `trunc10(SHA256(expanded_name))`. This, not the full digest, is what the wire
    /// carries and what lookups must key on.
    pub fn name_hash(&self) -> NameHash {
        self.name_hash
    }

    /// The destination hash for this name under a given identity.
    pub fn destination_hash(&self, identity: &Identity) -> AddressHash {
        destination_hash(self.name_hash, identity.hash())
    }
}

impl core::fmt::Debug for DestinationName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DestinationName({})", self.expanded)
    }
}

/// `trunc16(SHA256(name_hash || identity_hash))`.
///
/// Exposed separately from [`DestinationName::destination_hash`] because a receiver
/// validating an announce has the two hashes but not the name they came from: the wire
/// carries the name *hash*, and the plaintext name is unrecoverable.
pub fn destination_hash(name_hash: NameHash, identity_hash: AddressHash) -> AddressHash {
    let mut buf = [0u8; crate::hash::NAME_HASH_LEN + crate::hash::ADDRESS_HASH_LEN];
    buf[..crate::hash::NAME_HASH_LEN].copy_from_slice(name_hash.as_slice());
    buf[crate::hash::NAME_HASH_LEN..].copy_from_slice(identity_hash.as_slice());
    AddressHash::of(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aspects_join_with_dots() {
        let n = DestinationName::new("example_utilities", ["announcesample", "fruits"]);
        assert_eq!(n.expanded(), "example_utilities.announcesample.fruits");
    }

    #[test]
    fn no_aspects_is_just_the_app_name() {
        let n = DestinationName::new("retinue", Vec::<&str>::new());
        assert_eq!(n.expanded(), "retinue");
    }
}
