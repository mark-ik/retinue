//! Replay of fixtures captured from the RNS 1.3.8 reference implementation.
//!
//! These are the tests that matter. Everything else in the crate could be self-consistent
//! and still wrong on the wire; these compare against bytes a real RNS actually emitted.
//!
//! Regenerate with `oracle/.venv/Scripts/python.exe -u oracle/capture.py`. The fixtures
//! are committed, so this suite needs no Python.

use retinue::Error;
use retinue::announce::{self, Announce, RAND_HASH_LEN};
use retinue::destination::{DestinationName, destination_hash};
use retinue::hash::NameHash;
use retinue::identity::PrivateIdentity;
use retinue::packet::{Packet, PacketType};
use retinue::token;

/// The fixed private identity the oracle used. x25519_secret(32) || ed25519_seed(32).
const SEED_HEX: &str = concat!(
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c",
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c",
);

fn seed() -> [u8; 64] {
    let mut out = [0u8; 64];
    hex::decode_to_slice(SEED_HEX, &mut out).expect("valid hex");
    out
}

fn identity() -> PrivateIdentity {
    PrivateIdentity::from_secret_bytes(&seed())
}

fn fixture(name: &str) -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    std::fs::read(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("missing fixture {name}: {e}. Run oracle/capture.py."))
}

// ---------------------------------------------------------------- identity and hashing

#[test]
fn identity_derives_the_public_key_rns_derived() {
    let id = identity();
    assert_eq!(
        hex::encode(id.public().to_public_bytes()),
        "a8fd56cbca13577c24914cc4c13308b7d7f3e20bd39c55a4e636984655be3438\
         84f6da8c37b5f343568b185a20c63b5bf011a3d60ee805bb9e151371ea1d5555",
    );
}

#[test]
fn identity_hash_is_trunc16_sha256_of_the_public_key() {
    assert_eq!(
        identity().hash().to_string(),
        "70de4e01d8064fae79daa0e198233f56"
    );
}

/// The known-answer test. RNS and the Beechat crate independently agree on this value, and
/// now so do we. If this ever fails, the naming or hashing chain has drifted and every
/// address we compute is wrong.
#[test]
fn beechat_and_rns_destination_hash_vector() {
    let id = identity();
    let name = DestinationName::new("example_utilities", ["announcesample", "fruits"]);
    assert_eq!(name.expanded(), "example_utilities.announcesample.fruits");
    assert_eq!(
        name.destination_hash(id.public()).to_string(),
        "2419dca3c93718497b91990373df1503",
    );
}

#[test]
fn retinue_test_destination_hash() {
    let id = identity();
    let name = DestinationName::new("retinue", ["test"]);
    assert_eq!(name.name_hash().to_string(), "46d1eba5f26ba9153518");
    assert_eq!(
        name.destination_hash(id.public()).to_string(),
        "a8725a7e212dace39e9f99a8ac5da28c",
    );
}

// ---------------------------------------------------------------- announces

/// Every announce RNS emitted must decode and verify.
#[test]
fn rns_announces_validate() {
    for (name, ratcheted, app_data) in [
        ("announce_plain.bin", false, &b""[..]),
        ("announce_appdata.bin", false, &b"retinue-r0-fixture"[..]),
        ("announce_ratchet.bin", true, &b""[..]),
        (
            "announce_ratchet_appdata.bin",
            true,
            &b"retinue-r0-fixture"[..],
        ),
    ] {
        let raw = fixture(name);
        let packet = Packet::decode(&raw).unwrap_or_else(|e| panic!("{name}: decode: {e}"));

        assert_eq!(packet.packet_type, PacketType::Announce, "{name}");
        assert_eq!(packet.context_flag, ratcheted, "{name}: context flag");
        assert_eq!(packet.hops, 0, "{name}");

        let a = Announce::decode(&packet).unwrap_or_else(|e| panic!("{name}: validate: {e}"));

        assert_eq!(a.app_data, app_data, "{name}: app_data");
        assert_eq!(a.ratchet.is_some(), ratcheted, "{name}: ratchet presence");
        assert_eq!(
            a.destination.to_string(),
            "a8725a7e212dace39e9f99a8ac5da28c",
            "{name}"
        );
        assert_eq!(a.name_hash.to_string(), "46d1eba5f26ba9153518", "{name}");
        assert_eq!(a.identity.hash(), identity().hash(), "{name}");

        // Re-encoding must reproduce the original bytes exactly.
        assert_eq!(
            packet.encode(),
            raw,
            "{name}: re-encode is not byte-identical"
        );
    }
}

/// A ratcheted announce carries exactly one more field, 32 bytes, and it is signed.
#[test]
fn ratchet_is_thirty_two_bytes_and_signed() {
    let plain = Packet::decode(&fixture("announce_plain.bin")).unwrap();
    let ratchet = Packet::decode(&fixture("announce_ratchet.bin")).unwrap();

    assert_eq!(plain.payload.len(), 148);
    assert_eq!(ratchet.payload.len(), 180);
    assert_eq!(ratchet.payload.len() - plain.payload.len(), 32);

    let a = Announce::decode(&ratchet).unwrap();
    let r = a.ratchet.expect("ratcheted announce carries a ratchet");

    // The ratchet sits at payload[84..116], between rand_hash and the signature.
    assert_eq!(&ratchet.payload[84..116], &r[..]);

    // And the ratchet id is the truncated hash of it.
    assert_eq!(a.ratchet_id().unwrap(), NameHash::of(&r));
}

/// Every corrupted announce must be rejected. If any of these passes, retinue has a
/// security bug: a peer could announce an identity it does not hold, or tamper with the
/// app_data bound to one.
#[test]
fn corrupted_announces_are_rejected() {
    for name in [
        "announce_invalid_pubkey.bin",
        "announce_invalid_namehash.bin",
        "announce_invalid_randhash.bin",
        "announce_invalid_signature.bin",
        "announce_invalid_appdata.bin",
        "announce_invalid_desthash.bin",
    ] {
        let raw = fixture(name);
        let result = Packet::decode(&raw).and_then(|p| Announce::decode(&p).map(|_| ()));
        assert!(
            result.is_err(),
            "{name} was ACCEPTED. RNS rejects it; so must we.",
        );
    }
}

/// The `desthash` fixture flips a byte in the packet *header*, not the payload. It must
/// still fail, which is only possible because the destination hash is part of the signed
/// message. This test is the guard on the subtlest fact in the protocol.
#[test]
fn a_flipped_header_byte_breaks_the_signature() {
    let packet = Packet::decode(&fixture("announce_invalid_desthash.bin")).unwrap();
    assert_eq!(
        Announce::decode(&packet).unwrap_err(),
        Error::BadSignature,
        "corrupting the destination hash must fail the signature, not merely mismatch",
    );
}

// ---------------------------------------------------------------- round trip

/// Announces we build must be byte-identical to the ones RNS builds from the same inputs.
/// This is the direction that matters for interop: it is not enough to read RNS, we have
/// to be indistinguishable from it when we write.
#[test]
fn announces_we_build_match_rns_byte_for_byte() {
    for (name, ratcheted, app_data) in [
        ("announce_plain.bin", false, &b""[..]),
        ("announce_appdata.bin", false, &b"retinue-r0-fixture"[..]),
        ("announce_ratchet.bin", true, &b""[..]),
        (
            "announce_ratchet_appdata.bin",
            true,
            &b"retinue-r0-fixture"[..],
        ),
    ] {
        let raw = fixture(name);
        let original = Packet::decode(&raw).unwrap();
        let decoded = Announce::decode(&original).unwrap();

        // Reuse the oracle's rand_hash and ratchet so the output is comparable; those are
        // the only non-deterministic inputs.
        let rand_hash: [u8; RAND_HASH_LEN] = decoded.rand_hash;
        let rebuilt = announce::build(
            &identity(),
            decoded.name_hash,
            &rand_hash,
            decoded.ratchet.as_ref(),
            &decoded.app_data,
        );

        assert_eq!(
            rebuilt.encode(),
            raw,
            "{name}: our announce differs from the one RNS produced from the same inputs",
        );
        assert_eq!(rebuilt.context_flag, ratcheted, "{name}");
        assert!(!app_data.is_empty() || decoded.app_data.is_empty());
    }
}

// ---------------------------------------------------------------- token

/// Decrypt a token RNS encrypted to our identity. The token is non-deterministic (random
/// ephemeral key and IV) so we cannot byte-match it; decrypting it is the real test, and
/// it exercises the ECDH, the HKDF salt, the key split, the AES size, and the HMAC all at
/// once. If any one of those is wrong, this fails.
#[test]
fn we_can_decrypt_a_token_rns_encrypted_to_us() {
    let plaintext = token::decrypt_to_identity(&identity(), &fixture("token_identity.bin"))
        .expect("decrypting an RNS token");
    assert_eq!(
        plaintext,
        b"retinue token fixture, long enough to span two AES blocks",
    );
}

#[test]
fn a_tampered_token_is_rejected() {
    let mut raw = fixture("token_identity.bin");
    let n = raw.len();
    raw[n - 40] ^= 0xFF; // inside the ciphertext, before the MAC
    assert_eq!(
        token::decrypt_to_identity(&identity(), &raw).unwrap_err(),
        Error::BadMac,
    );
}

// ---------------------------------------------------------------- naming

#[test]
fn destination_hash_is_a_hash_of_two_hashes() {
    let id = identity();
    let name = DestinationName::new("retinue", ["test"]);
    assert_eq!(
        destination_hash(name.name_hash(), id.hash()),
        name.destination_hash(id.public()),
    );
}
