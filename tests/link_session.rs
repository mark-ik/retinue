//! R3 link establishment, replayed against a real RNS 1.3.8 session.
//!
//! The fixtures are deterministic from a fixed initiator ephemeral seed (RNS's ephemeral
//! key is random per run, but it is captured in the proof). This test reproduces the whole
//! derivation and decrypts a link data packet RNS encrypted to us. If the proof parsing,
//! the signature check, the ECDH, the HKDF, or the token format is wrong, it fails.
//!
//! Regenerate with `oracle/.venv/Scripts/python.exe -u oracle/capture_link_session.py`.

use retinue::destination::DestinationName;
use retinue::hash::AddressHash;
use retinue::identity::PrivateIdentity;
use retinue::link::{LinkMode, LinkTrailer, PendingLink};
use retinue::packet::Packet;

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("missing fixture {name}: {e}. Run capture_link_session.py."))
}

/// Values from `link_session.json`, pinned here so the test is self-contained.
const DEST_IDENTITY_SEED: &str = concat!(
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c",
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c",
);
const EPHEMERAL_SEED: &str = concat!(
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
);
const LINK_ID: &str = "884427832578c7b9f18142069008daae";
const EXPECTED_REPLY: &[u8] = b"reply-from-rns-over-the-link";

fn hex64(s: &str) -> [u8; 64] {
    let mut b = [0u8; 64];
    hex::decode_to_slice(s, &mut b).unwrap();
    b
}

/// The destination's public identity, which is all we need to open a link to it and to
/// verify its proof. In practice this comes from an announce.
fn peer_identity() -> retinue::Identity {
    *PrivateIdentity::from_secret_bytes(&hex64(DEST_IDENTITY_SEED)).public()
}

/// The `retinue.test` destination hash under that identity, which the link is opened to.
fn destination_hash() -> AddressHash {
    DestinationName::new("retinue", ["test"]).destination_hash(&peer_identity())
}

/// Reproduce establishment from the fixed inputs and the captured proof, then use the
/// resulting link to decrypt the data packet RNS sent. This is the whole R3 crypto path in
/// one test.
#[test]
fn we_establish_a_link_and_decrypt_rns_link_data() {
    let (pending, request) = PendingLink::open(
        destination_hash(),
        peer_identity(),
        &hex64(EPHEMERAL_SEED),
        LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
    );

    // Sanity: the request we build must yield the link id RNS agreed on.
    assert_eq!(pending.link_id().to_string(), LINK_ID);
    let _ = request;

    let proof = Packet::decode(&fixture("link_proof.bin")).unwrap();
    let link = pending
        .prove(&proof)
        .expect("RNS's proof must verify and establish the link");

    assert_eq!(link.id().to_string(), LINK_ID);
    assert_eq!(link.mode(), LinkMode::Aes256Cbc);
    assert_eq!(link.mtu(), 500);

    let data = Packet::decode(&fixture("link_rns_data.bin")).unwrap();
    let plaintext = link.decrypt(&data).expect("decrypting RNS's link data");
    assert_eq!(plaintext, EXPECTED_REPLY);
}

/// A proof with a flipped signature byte must not establish a link.
#[test]
fn a_tampered_proof_is_rejected() {
    let (pending, _) = PendingLink::open(
        destination_hash(),
        peer_identity(),
        &hex64(EPHEMERAL_SEED),
        LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: 500 },
    );

    let mut raw = fixture("link_proof.bin");
    raw[19 + 5] ^= 0xFF; // inside the signature
    let proof = Packet::decode(&raw).unwrap();
    assert!(pending.prove(&proof).is_err());
}
