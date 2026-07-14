"""Capture a full link session from RNS 1.3.8 into deterministic fixtures.

Same black-box discipline: we run RNS, we never read its source. We do call its documented
static helpers to cross-check, and we let its packet callback be the oracle.

We are the initiator with a FIXED ephemeral seed, so the whole derivation is reproducible
from our side. RNS's ephemeral key is random per run, but it arrives in the proof, which we
capture; combined with our fixed secret the shared key is fully determined. A committed
Rust test then reproduces the derivation and decrypts the captured RNS reply, with no
Python at test time.

Writes to ../tests/fixtures/:
  link_proof.bin          the raw proof packet RNS sent
  link_rns_data.bin       a link data packet RNS encrypted to us
  link_session.json       the fixed inputs and expected outputs

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_link_session.py
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad
import hashlib
import hmac as hmaclib

import RNS

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)
PORT = 42691
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20

# Our initiator's ephemeral seed, fixed. x25519_secret(32) || ed25519_seed(32).
EPH_SEED = bytes([0x33] * 32) + bytes([0x44] * 32)
EPH_X_PRIV = X25519PrivateKey.from_private_bytes(EPH_SEED[:32])
EPH_X_PUB = EPH_X_PRIV.public_key().public_bytes_raw()
EPH_ED_PUB = Ed25519PrivateKey.from_private_bytes(EPH_SEED[32:]).public_key().public_bytes_raw()

REPLY = b"reply-from-rns-over-the-link"

state: dict = {}
established = threading.Event()


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

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)

    cfg = Path(tempfile.mkdtemp(prefix="retinue-links-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[cli]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {PORT}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))

    identity = RNS.Identity.from_bytes(SEED)
    rns_ed_pub = identity.get_public_key()[32:64]

    def on_link(link):
        state["link"] = link

        def on_packet(message, packet):
            # Reply deterministically, so the Rust test can decrypt a known plaintext.
            RNS.Packet(link, REPLY).send()
        link.set_packet_callback(on_packet)
        established.set()

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
        print("RNS never connected"); RNS.exit(); return 1
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

    # request
    req_payload = EPH_X_PUB + EPH_ED_PUB + bytes([0x20, 0x01, 0xf4])
    lr = bytes([0x02, 0x00]) + dest.hash + bytes([0x00]) + req_payload
    link_id = hashlib.sha256(bytes([0x02]) + dest.hash + bytes([0x00]) + req_payload[:64]).digest()[:16]

    # cross-check with RNS's own helper
    pkt = RNS.Packet(None, None); pkt.raw = lr; pkt.unpack()
    assert RNS.Link.link_id_from_lr_packet(pkt) == link_id, "link_id disagrees with RNS"
    print(f"link_id {link_id.hex()} (cross-checked against RNS helper)")

    sock.sendall(frame(lr))

    proof = None
    for _ in range(120):
        for f in deframe(bytes(rx)):
            if len(f) >= 19 and f[0] & 0b11 == 3:
                proof = f; break
        if proof:
            break
        time.sleep(0.05)
    if proof is None:
        print("no proof"); stop.set(); RNS.exit(); return 1

    rns_eph_x = proof[19 + 64:19 + 96]
    shared = EPH_X_PRIV.exchange(X25519PublicKey.from_public_bytes(rns_eph_x))
    derived = HKDF(algorithm=hashes.SHA256(), length=64, salt=link_id, info=None).derive(shared)
    sk, ek = derived[:32], derived[32:]

    # RTT, then a data packet to trigger RNS's reply.
    rtt = token_encrypt(sk, ek, b"\xca" + struct.pack(">f", 0.05), bytes([0x55] * 16))
    sock.sendall(frame(bytes([0x0c, 0x00]) + link_id + bytes([0xfe]) + rtt))
    time.sleep(0.4)
    data = token_encrypt(sk, ek, b"ping", bytes([0x66] * 16))
    sock.sendall(frame(bytes([0x0c, 0x00]) + link_id + bytes([0x00]) + data))

    established.wait(timeout=5)
    time.sleep(1.5)

    # capture RNS's encrypted reply
    reply_pkt = None
    for f in deframe(bytes(rx)):
        if len(f) >= 19 and (f[0] & 0b11) == 0 and f[2:18] == link_id and f[18] == 0x00:
            if f[19:] == data:
                continue
            reply_pkt = f
    if reply_pkt is None:
        print("no reply captured"); stop.set(); RNS.exit(); return 1

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "link_proof.bin").write_bytes(proof)
    (FIXTURES / "link_rns_data.bin").write_bytes(reply_pkt)
    (FIXTURES / "link_session.json").write_text(json.dumps({
        "description": (
            "A full link session captured from RNS 1.3.8, deterministic from a fixed "
            "initiator ephemeral seed. link_proof.bin is RNS's proof; link_rns_data.bin is "
            "a link data packet RNS encrypted to us. A Rust test reproduces the derivation "
            "and decrypts the reply."
        ),
        "rns_version": RNS.__version__,
        "destination_identity_seed_hex": SEED.hex(),
        "destination_ed25519_pub_hex": rns_ed_pub.hex(),
        "initiator_ephemeral_seed_hex": EPH_SEED.hex(),
        "link_request_hex": lr.hex(),
        "link_id_hex": link_id.hex(),
        "requested_trailer_hex": "2001f4",
        "expected_reply_plaintext": REPLY.decode(),
    }, indent=2) + "\n", encoding="utf-8")

    print(f"link established: {established.is_set()}")
    print(f"wrote link_proof.bin ({len(proof)}B), link_rns_data.bin ({len(reply_pkt)}B), link_session.json")
    stop.set(); sock.close(); RNS.exit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
