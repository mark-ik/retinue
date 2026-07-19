"""Capture RNS 1.3.8's link IDENTIFY: how a link initiator proves its identity to the
responder, so the responder can validate the initiator's data-packet proofs.

Black-box: we hand-drive the initiator (fixed ephemeral seed), establish a link to RNS the
responder, then send an IDENTIFY packet (context LINKIDENTIFY = 251) built per a hypothesis.
RNS fires its `remote_identified_callback` iff it accepts the identify — so the callback
firing with our identity hash confirms the wire format, key, and signed message at once.

Hypotheses tried, in order, for the (sealed) payload and the signed message:
  * payload = public_key(64) || signature(64)
  * signed  = link_id(16) || public_key(64)   [bind identity to this link]  -- primary
  *           link_id only; public_key only; link_id||public_key with unsealed payload.

`public_key` is x25519_pub(32) || ed25519_pub(32), RNS's identity public form. The signature
is Ed25519 by our identity key (a fixed seed, distinct from the link-ephemeral key).

Writes ../tests/fixtures/link_identify.json.

    ./.venv/Scripts/python.exe -u capture_identify.py
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad
import hmac as hmaclib

import RNS

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)
PORT = 42698
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20
CTX_IDENTIFY = 0xFB  # RNS Packet.LINKIDENTIFY = 251

EPH_SEED = bytes([0x33] * 32) + bytes([0x44] * 32)
EPH_X_PRIV = X25519PrivateKey.from_private_bytes(EPH_SEED[:32])
EPH_X_PUB = EPH_X_PRIV.public_key().public_bytes_raw()
EPH_ED_PUB = Ed25519PrivateKey.from_private_bytes(EPH_SEED[32:]).public_key().public_bytes_raw()

# Our real (identifying) identity — a fixed seed, distinct from the link-ephemeral keys.
MY_SEED = bytes([0x11] * 32) + bytes([0x22] * 32)
MY_X_PRIV = X25519PrivateKey.from_private_bytes(MY_SEED[:32])
MY_ED_PRIV = Ed25519PrivateKey.from_private_bytes(MY_SEED[32:])
MY_PUB = MY_X_PRIV.public_key().public_bytes_raw() + MY_ED_PRIV.public_key().public_bytes_raw()
MY_IDENTITY_HASH = hashlib.sha256(MY_PUB).digest()[:16]


def frame(p):
    out = bytearray([FLAG])
    for b in p:
        out += bytes([ESC, b ^ ESC_MASK]) if b in (FLAG, ESC) else bytes([b])
    out.append(FLAG)
    return bytes(out)


def deframe(stream):
    frames, cur, inf, esc = [], bytearray(), False, False
    for b in stream:
        if b == FLAG:
            if inf and cur:
                frames.append(bytes(cur))
            cur, inf, esc = bytearray(), True, False
        elif not inf:
            continue
        elif esc:
            cur.append(b ^ ESC_MASK); esc = False
        elif b == ESC:
            esc = True
        else:
            cur.append(b)
    return frames


def token_encrypt(sk, ek, pt, iv):
    pad = sympad.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(ek), modes.CBC(iv)).encryptor()
    body = iv + ct.update(pad.update(pt) + pad.finalize()) + ct.finalize()
    return body + hmaclib.new(sk, body, hashlib.sha256).digest()


def main() -> int:
    print(f"RNS {RNS.__version__}")
    print(f"our identity hash {MY_IDENTITY_HASH.hex()}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)

    cfg = Path(tempfile.mkdtemp(prefix="retinue-identify-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[cli]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {PORT}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    identity = RNS.Identity.from_bytes(SEED)

    identified = {"hash": None}

    def on_link(link):
        def on_ident(lk, ident):
            identified["hash"] = ident.hash
            print(f"RNS identified the remote as {ident.hash.hex()}")
        link.set_remote_identified_callback(on_ident)

    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test")
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    dest.set_link_established_callback(on_link)
    dest.accepts_links(True)
    print(f"destination {dest.hash.hex()}")

    sock = None
    for _ in range(20):
        try:
            sock, _ = srv.accept(); break
        except TimeoutError:
            continue
    if sock is None:
        print("no RNS connection"); RNS.exit(); return 1
    sock.settimeout(0.5)
    rx = bytearray()
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                c = sock.recv(65536)
                if not c:
                    break
                rx.extend(c)
            except TimeoutError:
                continue
            except OSError:
                break
    threading.Thread(target=reader, daemon=True).start()

    req_payload = EPH_X_PUB + EPH_ED_PUB + bytes([0x20, 0x01, 0xf4])
    lr = bytes([0x02, 0x00]) + dest.hash + bytes([0x00]) + req_payload
    link_id = hashlib.sha256(bytes([0x02]) + dest.hash + bytes([0x00]) + req_payload[:64]).digest()[:16]
    sock.sendall(frame(lr))

    lrproof = None
    for _ in range(120):
        for f in deframe(bytes(rx)):
            if len(f) >= 19 and f[0] & 0b11 == 3:
                lrproof = f; break
        if lrproof:
            break
        time.sleep(0.05)
    if lrproof is None:
        print("no link proof"); stop.set(); RNS.exit(); return 1

    rns_eph_x = lrproof[19 + 64:19 + 96]
    shared = EPH_X_PRIV.exchange(X25519PublicKey.from_public_bytes(rns_eph_x))
    derived = HKDF(algorithm=hashes.SHA256(), length=64, salt=link_id, info=None).derive(shared)
    sk, ek = derived[:32], derived[32:]

    rtt = token_encrypt(sk, ek, b"\xca" + struct.pack(">f", 0.05), bytes([0x55] * 16))
    sock.sendall(frame(bytes([0x0c, 0x00]) + link_id + bytes([0xfe]) + rtt))
    time.sleep(0.5)

    winning_sig = {"hex": None}

    def send_identify(signed_msg: bytes, sealed: bool):
        signature = MY_ED_PRIV.sign(signed_msg)
        winning_sig["hex"] = signature.hex()
        payload = MY_PUB + signature
        body = token_encrypt(sk, ek, payload, bytes([0x77] * 16)) if sealed else payload
        sock.sendall(frame(bytes([0x0c, 0x00]) + link_id + bytes([CTX_IDENTIFY]) + body))

    candidates = [
        ("sealed_sig_over_linkid_pub", link_id + MY_PUB, True),
        ("sealed_sig_over_linkid", link_id, True),
        ("sealed_sig_over_pub", MY_PUB, True),
        ("unsealed_sig_over_linkid_pub", link_id + MY_PUB, False),
    ]
    results = []
    winner = None
    for name, msg, sealed in candidates:
        send_identify(msg, sealed)
        time.sleep(1.5)
        ok = identified["hash"] == MY_IDENTITY_HASH
        results.append({"candidate": name, "sealed": sealed, "accepted": ok})
        print(f"  {name}: accepted={ok}")
        if ok:
            winner = name
            break

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "link_identify.json").write_text(json.dumps({
        "description": (
            "RNS 1.3.8 link IDENTIFY (context LINKIDENTIFY = 251). Our hand-driven initiator "
            "sent an identify built per each candidate; RNS's remote_identified_callback firing "
            "with our identity hash marks the wire-correct one (payload, signed message, and "
            "whether it is sealed with the link key)."
        ),
        "rns_version": RNS.__version__,
        "context_identify": CTX_IDENTIFY,
        "link_id_hex": link_id.hex(),
        "our_identity_public_hex": MY_PUB.hex(),
        "our_identity_hash_hex": MY_IDENTITY_HASH.hex(),
        "our_identity_secret_seed_hex": MY_SEED.hex(),
        "signed_message": "link_id(16) || public_key(64)",
        "signature_hex": winning_sig["hex"],
        "payload_layout": "public_key(64) || signature(64), sealed with the link key",
        "candidates": results,
        "winner": winner,
    }, indent=2) + "\n", encoding="utf-8")

    print(f"winner: {winner}")
    stop.set(); sock.close(); RNS.exit()
    return 0 if winner else 2


if __name__ == "__main__":
    raise SystemExit(main())
