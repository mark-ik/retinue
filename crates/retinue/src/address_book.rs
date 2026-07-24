//! The address book: learning peers from announces.
//!
//! A destination hash cannot be turned back into an identity, so to reach a peer you must
//! have heard it announce. The address book ingests validated [`Announce`]s and answers the
//! question a link needs: given a destination hash, what is the identity (to verify its
//! proof) and its current ratchet?
//!
//! This is pure state over [`Announce`], which is itself already validated on decode, so an
//! entry only ever comes from an announce whose signature checked out. Cadence and I/O live
//! in the tokio shell above; this holds no timers and does no network.

use std::collections::HashMap;

use crate::announce::{Announce, RATCHET_LEN};
use crate::hash::{AddressHash, NameHash};
use crate::identity::Identity;

/// What the book knows about one destination.
#[derive(Clone, Debug)]
pub struct Peer {
    /// The destination's identity, enough to verify a link proof from it.
    pub identity: Identity,
    /// The destination's name hash, as announced.
    pub name_hash: NameHash,
    /// The most recently announced app data.
    pub app_data: Vec<u8>,
    /// The destination's current ratchet public key, if it advertises ratchets. Kept so a
    /// single-packet encryption to this destination can use the ratchet rather than the
    /// long-term key.
    pub ratchet: Option<[u8; RATCHET_LEN]>,
    /// How many announces for this destination have been ingested. A cheap freshness and
    /// liveness signal without a clock, which this layer deliberately does not have.
    pub announces_seen: u64,
}

/// A store of peers learned from announces, keyed by destination hash.
#[derive(Default)]
pub struct AddressBook {
    peers: HashMap<AddressHash, Peer>,
}

impl AddressBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an announce. A later announce for the same destination refreshes the entry
    /// (app data, ratchet) and bumps the count. Because [`Announce`] only exists once its
    /// signature has verified, ingesting one cannot poison the book with a forged identity.
    pub fn ingest(&mut self, announce: &Announce) {
        self.peers
            .entry(announce.destination)
            .and_modify(|p| {
                p.identity = announce.identity;
                p.name_hash = announce.name_hash;
                p.app_data = announce.app_data.clone();
                p.ratchet = announce.ratchet;
                p.announces_seen += 1;
            })
            .or_insert_with(|| Peer {
                identity: announce.identity,
                name_hash: announce.name_hash,
                app_data: announce.app_data.clone(),
                ratchet: announce.ratchet,
                announces_seen: 1,
            });
    }

    /// Resolve a destination hash to what we know about it.
    pub fn resolve(&self, destination: AddressHash) -> Option<&Peer> {
        self.peers.get(&destination)
    }

    /// Whether we can reach a destination, i.e. have heard it announce.
    pub fn knows(&self, destination: AddressHash) -> bool {
        self.peers.contains_key(&destination)
    }

    /// Every destination currently known.
    pub fn destinations(&self) -> impl Iterator<Item = AddressHash> + '_ {
        self.peers.keys().copied()
    }

    /// Number of destinations known.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Forget a destination, e.g. after it has been unreachable past a policy the shell
    /// enforces.
    pub fn forget(&mut self, destination: AddressHash) -> Option<Peer> {
        self.peers.remove(&destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    fn announce(fixture: &str) -> Announce {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
        let raw = std::fs::read(format!("{path}{fixture}")).unwrap();
        Announce::decode(&Packet::decode(&raw).unwrap()).unwrap()
    }

    #[test]
    fn ingest_and_resolve_a_real_announce() {
        let a = announce("announce_appdata.bin");
        let mut book = AddressBook::new();
        assert!(!book.knows(a.destination));
        book.ingest(&a);

        let peer = book.resolve(a.destination).expect("resolved");
        assert_eq!(peer.identity.hash(), a.identity.hash());
        assert_eq!(peer.app_data, b"retinue-r0-fixture");
        assert_eq!(peer.announces_seen, 1);
        assert!(peer.ratchet.is_none());
    }

    #[test]
    fn a_ratcheted_announce_carries_its_ratchet() {
        let a = announce("announce_ratchet.bin");
        let mut book = AddressBook::new();
        book.ingest(&a);
        assert!(book.resolve(a.destination).unwrap().ratchet.is_some());
    }

    #[test]
    fn re_ingesting_refreshes_rather_than_duplicates() {
        let plain = announce("announce_plain.bin");
        let with_data = announce("announce_appdata.bin");
        // Same identity and name, so same destination hash.
        assert_eq!(plain.destination, with_data.destination);

        let mut book = AddressBook::new();
        book.ingest(&plain);
        book.ingest(&with_data);
        assert_eq!(book.len(), 1);
        let peer = book.resolve(plain.destination).unwrap();
        assert_eq!(peer.announces_seen, 2);
        assert_eq!(peer.app_data, b"retinue-r0-fixture"); // the later one won
    }
}
