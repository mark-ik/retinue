"""Capture R0 wire fixtures from the RNS reference implementation.

BLACK-BOX DISCIPLINE
--------------------
We run RNS. We never read its source. Every fact recorded here comes from calling the
public API documented in the Reticulum manual, or from bytes RNS produced. Constants are
read off live class objects, which observes the running system rather than its code.
Nothing under `.venv/` is ever opened.

This matters because retinue is a clean-room reimplementation: the provenance of every
byte-level fact has to be defensible.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture.py

(-u matters: RNS.exit() hard-exits the process and would discard buffered stdout.)

Writes fixtures and a manifest to ../tests/fixtures/.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

import RNS

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

# A fixed 64-byte private identity: X25519 secret (32) then Ed25519 seed (32). Chosen to
# match the Beechat crate's `compare_announce` test vector, so both implementations can be
# diffed against the same input.
SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)

# The Beechat test's destination, so its printed hash is directly comparable.
BEECHAT_APP, BEECHAT_ASPECTS = "example_utilities", ("announcesample", "fruits")
BEECHAT_EXPECTED_HASH = "2419dca3c93718497b91990373df1503"

# retinue's own test destination.
APP, ASPECTS = "retinue", ("test",)

APP_DATA = b"retinue-r0-fixture"

manifest: dict = {}
notes: list[str] = []


def emit(name: str, data: bytes, description: str, **extra) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / name).write_bytes(data)
    manifest.setdefault("fixtures", {})[name] = {
        "description": description,
        "size": len(data),
        **extra,
    }
    print(f"  wrote {name}  ({len(data)} bytes)")


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    cfgdir = Path(tempfile.mkdtemp(prefix="retinue-oracle-"))
    (cfgdir / "config").write_text(
        "[reticulum]\n"
        "  enable_transport = No\n"
        "  share_instance = No\n"
        "  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 3\n"
        "\n[interfaces]\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfgdir))
    try:
        return run()
    finally:
        RNS.exit()
        shutil.rmtree(cfgdir, ignore_errors=True)


def run() -> int:
    # ------------------------------------------------------------------ constants
    constants = {
        "Identity.KEYSIZE_bits": RNS.Identity.KEYSIZE,
        "Identity.RATCHETSIZE_bits": RNS.Identity.RATCHETSIZE,
        "Identity.TRUNCATED_HASHLENGTH_bits": RNS.Identity.TRUNCATED_HASHLENGTH,
        "Identity.NAME_HASH_LENGTH_bits": RNS.Identity.NAME_HASH_LENGTH,
        "Identity.SIGLENGTH_bits": RNS.Identity.SIGLENGTH,
        "Identity.TOKEN_OVERHEAD_bytes": RNS.Identity.TOKEN_OVERHEAD,
        "Identity.DERIVED_KEY_LENGTH_bytes": RNS.Identity.DERIVED_KEY_LENGTH,
        "Reticulum.MTU": RNS.Reticulum.MTU,
        "Reticulum.MDU": RNS.Reticulum.MDU,
        "Reticulum.HEADER_MINSIZE": RNS.Reticulum.HEADER_MINSIZE,
        "Reticulum.HEADER_MAXSIZE": RNS.Reticulum.HEADER_MAXSIZE,
        "Reticulum.IFAC_MIN_SIZE": RNS.Reticulum.IFAC_MIN_SIZE,
        "Packet.ENCRYPTED_MDU": RNS.Packet.ENCRYPTED_MDU,
        "Packet.PLAIN_MDU": RNS.Packet.PLAIN_MDU,
        "Link.ECPUBSIZE": RNS.Link.ECPUBSIZE,
        "Link.KEYSIZE": RNS.Link.KEYSIZE,
        "Link.MDU": RNS.Link.MDU,
        "Link.LINK_MTU_SIZE": RNS.Link.LINK_MTU_SIZE,
        "Link.MODE_AES128_CBC": RNS.Link.MODE_AES128_CBC,
        "Link.MODE_AES256_CBC": RNS.Link.MODE_AES256_CBC,
        "Destination.RATCHET_COUNT": RNS.Destination.RATCHET_COUNT,
        "Destination.RATCHET_INTERVAL": RNS.Destination.RATCHET_INTERVAL,
    }
    manifest["constants"] = constants
    print("Constants (read off the live implementation):")
    for k, v in constants.items():
        print(f"  {k} = {v}")

    # ------------------------------------------------------------------ identity
    identity = RNS.Identity.from_bytes(SEED)
    if identity is None:
        print("FAILED: Identity.from_bytes returned None", file=sys.stderr)
        return 1

    pub = identity.get_public_key()
    salt = identity.get_salt()
    context = identity.get_context()

    beechat_name = RNS.Destination.expand_name(None, BEECHAT_APP, *BEECHAT_ASPECTS)
    beechat_hash = RNS.Destination.hash(identity, BEECHAT_APP, *BEECHAT_ASPECTS)
    beechat_ok = beechat_hash.hex() == BEECHAT_EXPECTED_HASH

    name = RNS.Destination.expand_name(None, APP, *ASPECTS)
    name_hash = hashlib.sha256(name.encode()).digest()[: RNS.Identity.NAME_HASH_LENGTH // 8]

    print("\nIdentity vector (deterministic):")
    print(f"  public key      {pub.hex()}")
    print(f"    x25519  [0:32]  {pub[0:32].hex()}")
    print(f"    ed25519 [32:64] {pub[32:64].hex()}")
    print(f"  identity hash   {identity.hash.hex()}")
    print(f"  hkdf salt       {salt.hex()}  (== identity hash: {salt == identity.hash})")
    print(f"  hkdf info       {context!r}")
    print(f"  {beechat_name} -> {beechat_hash.hex()}")
    print(f"  Beechat vector match: {beechat_ok}")
    notes.append(
        f"Beechat destination-hash vector {'MATCHES' if beechat_ok else 'DOES NOT MATCH'} RNS 1.3.8."
    )

    manifest["identity_vector"] = {
        "description": (
            "Deterministic identity from a fixed 64-byte private key, and every value RNS "
            "derives from it. retinue must reproduce all of these exactly."
        ),
        "private_key_hex": SEED.hex(),
        "private_key_layout": "x25519_secret(32) || ed25519_seed(32)",
        "public_key_hex": pub.hex(),
        "public_key_layout": "x25519_public(32) || ed25519_verifying(32)",
        "identity_hash_hex": identity.hash.hex(),
        "identity_hash_rule": "trunc16(sha256(public_key))",
        "hkdf_salt_hex": salt.hex(),
        "hkdf_salt_rule": "the identity hash",
        "hkdf_info": None,
        "destinations": {
            beechat_name: {
                "destination_hash_hex": beechat_hash.hex(),
                "beechat_crate_expected": BEECHAT_EXPECTED_HASH,
                "beechat_matches": beechat_ok,
            },
            name: {
                "app_name": APP,
                "aspects": list(ASPECTS),
                "name_hash_hex": name_hash.hex(),
                "destination_hash_hex": RNS.Destination.hash(identity, APP, *ASPECTS).hex(),
            },
        },
    }

    # ------------------------------------------------------------------ announces
    # One destination, announced four ways. RNS refuses to register the same destination
    # twice, so ratchets are toggled on the single instance rather than rebuilt.
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP, *ASPECTS)
    print(f"\nDestination {name} -> {dest.hash.hex()}  name_hash {dest.name_hash.hex()}")

    def shoot(tag: str, app_data, ratcheted: bool):
        pkt = dest.announce(app_data=app_data, send=False)
        if pkt is None:
            print(f"  [{tag}] announce() returned None", file=sys.stderr)
            return None
        if pkt.raw is None:
            pkt.pack()
        valid = RNS.Identity.validate_announce(pkt)
        ctx_flag = bool(pkt.raw[0] & 0b0010_0000)
        print(f"  [{tag:16s}] raw={len(pkt.raw):3d} payload={len(pkt.data):3d} "
              f"ctx_flag={int(ctx_flag)} rns_valid={valid}")
        emit(
            f"announce_{tag}.bin",
            pkt.raw,
            f"RNS 1.3.8 announce for {name}. ratchets={'on' if ratcheted else 'off'}, "
            f"app_data={'yes' if app_data else 'none'}. Full packet including the 19-byte header.",
            ratchets=ratcheted,
            app_data_hex=app_data.hex() if app_data else None,
            payload_len=len(pkt.data),
            context_flag=ctx_flag,
            rns_self_validates=bool(valid),
            destination_hash_hex=dest.hash.hex(),
        )
        return pkt

    print("\nAnnounces:")
    off = shoot("plain", None, False)
    off_ad = shoot("appdata", APP_DATA, False)

    rpath = Path(tempfile.mkdtemp(prefix="retinue-ratchet-")) / "ratchets"
    dest.enable_ratchets(str(rpath))

    on = shoot("ratchet", None, True)
    on_ad = shoot("ratchet_appdata", APP_DATA, True)

    if off and on:
        delta = len(on.data) - len(off.data)
        print("\n  Ratchet diff (the question this harness exists to answer):")
        print(f"    payload {len(off.data)} -> {len(on.data)}  ({delta:+d}, "
              f"RATCHETSIZE={RNS.Identity.RATCHETSIZE // 8})")
        print(f"    header byte0 {off.raw[0]:#010b} -> {on.raw[0]:#010b}  "
              f"(bit 5 = context flag)")
        print(f"    ratchet sits at payload[84:116], signature moves to [116:180]")
        notes.append(
            f"A ratcheted announce is +{delta} bytes; the 32-byte ratchet public key is "
            "inserted between rand_hash and the signature (payload[84:116]), and its presence "
            "is signalled by bit 5 of header byte 0 (the Context Flag)."
        )
        notes.append(
            "Beechat 0.1.0 models neither the context flag nor the ratchet, so it cannot parse "
            "or validate a ratcheted announce. Ratchets are off by default, which is the only "
            "reason a Beechat<->RNS pairing appears to work."
        )
        manifest["ratchet_diff"] = {
            "payload_len_without": len(off.data),
            "payload_len_with": len(on.data),
            "delta_bytes": delta,
            "ratchet_offset": [84, 116],
            "signature_offset_with_ratchet": [116, 180],
            "signature_offset_without_ratchet": [84, 148],
            "signalled_by": "bit 5 of header byte 0 (Context Flag)",
            "header_byte0_without": off.raw[0],
            "header_byte0_with": on.raw[0],
        }

    manifest["announce_layout"] = {
        "wire_payload": "x25519_pub(32) || ed25519_pub(32) || name_hash(10) || rand_hash(10) "
                        "|| [ratchet(32) if context_flag] || signature(64) || app_data(*)",
        "signed_message": "dest_hash(16) || x25519_pub(32) || ed25519_pub(32) || name_hash(10) "
                          "|| rand_hash(10) || [ratchet(32)] || app_data(*)",
        "signed_message_note": (
            "The signed message is the wire payload with the destination hash prepended and the "
            "signature spliced out. The destination hash is NOT in the payload: it comes from the "
            "packet header. Verified by independent Ed25519 verification against all four "
            "announce variants."
        ),
        "ratchet_id_rule": "trunc10(sha256(ratchet_public_key))",
    }

    # ------------------------------------------------------------------ invalid announces
    # Negative fixtures. If retinue accepts any of these, retinue has a security bug.
    print("\nInvalid announces (each MUST be rejected):")
    if off_ad is not None:
        base = off_ad.raw
        hdr = len(base) - len(off_ad.data)  # 19
        targets = {
            "pubkey": hdr + 5,
            "namehash": hdr + 64 + 2,
            "randhash": hdr + 74 + 2,
            "signature": hdr + 84 + 5,
            "appdata": len(base) - 3,
            "desthash": 5,  # in the header: signature covers it, so this must fail too
        }
        for what, off_i in targets.items():
            bad = bytearray(base)
            bad[off_i] ^= 0xFF
            bad = bytes(bad)
            pkt = RNS.Packet(None, None)
            pkt.raw = bad
            try:
                pkt.unpack()
                verdict = RNS.Identity.validate_announce(pkt)
            except Exception as exc:  # noqa: BLE001
                verdict = f"raised {type(exc).__name__}"
            rejected = verdict is not True
            print(f"  [{what:9s}] byte {off_i:3d} flipped -> {verdict!r} "
                  f"{'rejected (good)' if rejected else 'ACCEPTED (BAD)'}")
            emit(
                f"announce_invalid_{what}.bin",
                bad,
                f"announce_appdata.bin with byte {off_i} XOR 0xFF, corrupting the {what}. "
                f"MUST fail validation.",
                mutated_offset=off_i,
                corrupts=what,
                rns_rejects=bool(rejected),
            )
            if not rejected:
                notes.append(f"WARNING: RNS ACCEPTED a {what}-corrupted announce.")

    # ------------------------------------------------------------------ token
    print("\nToken (encrypt-to-identity):")
    plaintext = b"retinue token fixture, long enough to span two AES blocks"
    token = identity.encrypt(plaintext)
    back = identity.decrypt(token)
    print(f"  plaintext {len(plaintext)} -> token {len(token)} bytes; RNS round-trip ok: "
          f"{back == plaintext}")
    print(f"    ephemeral pub [0:32]   {token[0:32].hex()}")
    print(f"    iv            [32:48]  {token[32:48].hex()}")
    print(f"    ciphertext    [48:-32] {len(token[48:-32])} bytes")
    print(f"    hmac          [-32:]   {token[-32:].hex()}")
    emit(
        "token_identity.bin",
        token,
        "Identity.encrypt() output for a known plaintext under the fixed identity. "
        "Layout: ephemeral_x25519_pub(32) || IV(16) || AES-256-CBC/PKCS7 ciphertext || "
        "HMAC-SHA256(32). Non-deterministic (random ephemeral key and IV), so retinue cannot "
        "byte-match it. retinue must DECRYPT it: that is the real test.",
        plaintext_hex=plaintext.hex(),
        rns_roundtrip_ok=bool(back == plaintext),
    )
    manifest["token"] = {
        "layout": "ephemeral_x25519_pub(32) || IV(16) || AES-256-CBC/PKCS7 || HMAC-SHA256(32)",
        "kdf": "HKDF-SHA256(ikm=x25519_shared, salt=identity_hash(16), info=empty, len=64)",
        "key_split": "sign_key = derived[0:32] (HMAC-SHA256), enc_key = derived[32:64] (AES-256)",
        "hmac_covers": "IV || ciphertext  (the ephemeral public key is NOT authenticated)",
        "verified_by": (
            "Independent decryption in scratch/crypto_probe.py using `cryptography` alone, "
            "trying all four (aes_size x split_order) combinations. Only AES-256 with "
            "sign-key-first both authenticates and decrypts."
        ),
    }

    # ------------------------------------------------------------------ manifest
    manifest["rns_version"] = RNS.__version__
    manifest["provenance"] = (
        "Generated by oracle/capture.py against the RNS reference implementation, used strictly "
        "as a black box. RNS source was never read."
    )
    manifest["notes"] = notes
    (FIXTURES / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print("\nwrote manifest.json")
    print("\nNOTES:")
    for n in notes:
        print(f"  - {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
