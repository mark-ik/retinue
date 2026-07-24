"""Capture RNS 1.3.8's link-data PROOF authoritatively: make RNS prove a packet WE send,
and read the proof it emits — no guessing at the format.

Black-box: we run RNS and observe it. We hand-drive the link as initiator (fixed ephemeral
seed), then send RNS a proof-requesting Channel packet (context 14, a sealed envelope RNS's
channel expects). RNS's link proves the packet and sends a PROOF back. We capture that PROOF
frame and decode it: the destination field, the payload length (64 => implicit / 96 =>
explicit), and — the load-bearing unknown — WHICH key signs it. We validate the 64-byte
signature against every candidate public key we hold (RNS's identity Ed25519, and our own
link-ephemeral Ed25519) over every candidate message (full hash, truncated hash, packet
bytes). Whatever validates is the wire truth.

Writes ../tests/fixtures/rns_link_proof.json.

    ./.venv/Scripts/python.exe -u capture_rns_proof.py
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad
import hmac as hmaclib

import RNS
from RNS.Channel import MessageBase

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)
PORT = 42697
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20
CTX_CHANNEL = 0x0E

EPH_SEED = bytes([0x33] * 32) + bytes([0x44] * 32)
EPH_X_PRIV = X25519PrivateKey.from_private_bytes(EPH_SEED[:32])
EPH_X_PUB = EPH_X_PRIV.public_key().public_bytes_raw()
EPH_ED_PRIV = Ed25519PrivateKey.from_private_bytes(EPH_SEED[32:])
EPH_ED_PUB = EPH_ED_PRIV.public_key().public_bytes_raw()


class ProbeMessage(MessageBase):
    MSGTYPE = 0xABCD

    def __init__(self, payload: bytes = b""):
        self.payload = payload

    def pack(self) -> bytes:
        return self.payload

    def unpack(self, raw: bytes) -> None:
        self.payload = raw


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


def packet_hash(f: bytes) -> bytes:
    """retinue's verified hash of a header-type-1 wire packet: SHA256((flags&0x0f) ||
    destination(16) || context(1) || payload). Returns the full 32-byte digest."""
    return hashlib.sha256(bytes([f[0] & 0x0F]) + f[2:18] + f[18:19] + f[19:]).digest()


def envelope(msgtype: int, seq: int, payload: bytes) -> bytes:
    return msgtype.to_bytes(2, "big") + seq.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def main() -> int:
    print(f"RNS {RNS.__version__}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rnsproof-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[cli]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {PORT}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    identity = RNS.Identity.from_bytes(SEED)
    # RNS identity public key = X25519 pub (32) || Ed25519 pub (32); the signing half last.
    rns_pub = identity.get_public_key()
    rns_ed_pub = rns_pub[32:64]

    def on_link(link):
        # Register the message type so RNS's channel accepts our envelope; the proof itself
        # is a link-layer ack, but registering avoids the channel discarding the packet.
        try:
            link.get_channel().register_message_type(ProbeMessage)
        except Exception as ex:
            print("register:", ex)

    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test")
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    dest.set_link_established_callback(on_link)
    dest.accepts_links(True)
    print(f"destination {dest.hash.hex()}  rns_ed_pub {rns_ed_pub.hex()}")

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

    # Send RNS a proof-requesting Channel packet: a sealed envelope under context 14.
    mark = len(deframe(bytes(rx)))  # frames seen so far, to isolate what arrives after
    env = envelope(ProbeMessage.MSGTYPE, 0, b"hi")
    token = token_encrypt(sk, ek, env, bytes([0x66] * 16))
    sent = bytes([0x0c, 0x00]) + link_id + bytes([CTX_CHANNEL]) + token
    sent_hash = packet_hash(sent)  # what a proof of OUR packet would reference
    sock.sendall(frame(sent))
    print(f"sent channel packet, hash full={sent_hash.hex()} trunc={sent_hash[:16].hex()}")

    # Watch a few seconds for a PROOF-type packet from RNS (header bits == 3).
    time.sleep(4.0)
    proofs = []
    for f in deframe(bytes(rx))[mark:]:
        if len(f) >= 3 and (f[0] & 0b11) == 3:
            proofs.append(f)

    def validate(sig: bytes) -> str | None:
        candidates = {
            "rns_identity_ed25519": rns_ed_pub,
            "our_link_ephemeral_ed25519": EPH_ED_PUB,
        }
        messages = {
            "full_hash": sent_hash,
            "trunc_hash": sent_hash[:16],
            "packet_bytes": sent,
            "token": token,
        }
        for kname, kpub in candidates.items():
            pk = Ed25519PublicKey.from_public_bytes(kpub)
            for mname, msg in messages.items():
                try:
                    pk.verify(sig, msg)
                    return f"{kname} over {mname}"
                except InvalidSignature:
                    continue
        return None

    decoded = []
    for p in proofs:
        # A proof packet: [flags][hops][dest 16][context][payload...]; payload is the proof.
        dest_field = p[2:18].hex() if len(p) >= 18 else ""
        context = p[18] if len(p) >= 19 else None
        payload = p[19:] if len(p) >= 19 else b""
        entry = {
            "frame_hex": p.hex(),
            "flags": p[0],
            "dest_field_hex": dest_field,
            "dest_is_trunc_hash": dest_field == sent_hash[:16].hex(),
            "dest_is_link_id": dest_field == link_id.hex(),
            "context": context,
            "payload_len": len(payload),
        }
        # Implicit proof = 64-byte signature; explicit = 32-byte hash + 64-byte signature.
        if len(payload) == 64:
            entry["signature_validates_as"] = validate(payload)
        elif len(payload) == 96:
            entry["explicit_hash_hex"] = payload[:32].hex()
            entry["explicit_hash_matches"] = payload[:32].hex() == sent_hash.hex()
            entry["signature_validates_as"] = validate(payload[32:])
        decoded.append(entry)

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "rns_link_proof.json").write_text(json.dumps({
        "description": (
            "RNS 1.3.8 link-data PROOF, captured authoritatively: we sent RNS a "
            "proof-requesting channel packet and RNS proved it. Each proof frame is decoded; "
            "signature_validates_as names the (key, message) pair whose verification passed, "
            "which is the wire-truth of how a link data proof is signed."
        ),
        "rns_version": RNS.__version__,
        "link_id_hex": link_id.hex(),
        "our_sent_packet_hash_full_hex": sent_hash.hex(),
        "our_sent_packet_hash_trunc_hex": sent_hash[:16].hex(),
        "rns_identity_ed25519_pub_hex": rns_ed_pub.hex(),
        "prover_identity_public_hex": rns_pub.hex(),
        "prover_identity_secret_seed_hex": SEED.hex(),
        "proof_frames_seen": len(proofs),
        "proofs": decoded,
    }, indent=2) + "\n", encoding="utf-8")

    print(f"proof frames after our packet: {len(proofs)}")
    for d in decoded:
        print(f"  dest_trunc={d['dest_is_trunc_hash']} link={d['dest_is_link_id']} "
              f"ctx={d.get('context')} len={d['payload_len']} sig={d.get('signature_validates_as')}")
    stop.set(); sock.close(); RNS.exit()
    return 0 if any(d.get("signature_validates_as") for d in decoded) else 2


if __name__ == "__main__":
    raise SystemExit(main())
