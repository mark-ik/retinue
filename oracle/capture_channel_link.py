"""Capture RNS 1.3.8 Channel behaviour over a real link: the envelope on the wire,
and the acknowledgement mechanism.

Black-box discipline: we run RNS, never read its source. We are the link initiator with
a fixed ephemeral seed (so the derivation is reproducible), RNS is the responder. Once
the link is up we ask the RNS side to send a Channel message, and we observe the raw
context-14 (CHANNEL) packets it puts on the wire, decrypting them with the derived link
key. Then we deliberately do NOT respond, and watch whether RNS retransmits the same
envelope -- which tells us the ack mechanism:

  * If RNS retransmits the channel packet when we stay silent, its reliability is the
    link packet PROOF (each channel packet is proof-requesting; unproven => resend),
    not an explicit ack envelope. That is the hypothesis to confirm.

Writes ../tests/fixtures/channel_link.json.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_channel_link.py
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
import tempfile
from collections import Counter
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad
import hashlib
import hmac as hmaclib

import RNS
from RNS.Channel import MessageBase

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)
PORT = 42694
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20
CTX_CHANNEL = 0x0E

EPH_SEED = bytes([0x33] * 32) + bytes([0x44] * 32)
EPH_X_PRIV = X25519PrivateKey.from_private_bytes(EPH_SEED[:32])
EPH_X_PUB = EPH_X_PRIV.public_key().public_bytes_raw()
EPH_ED_PUB = Ed25519PrivateKey.from_private_bytes(EPH_SEED[32:]).public_key().public_bytes_raw()

CHANNEL_PAYLOAD = b"channel-hello"


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


def token_decrypt(sk, ek, token):
    body, tag = token[:-32], token[-32:]
    if not hmaclib.compare_digest(hmaclib.new(sk, body, hashlib.sha256).digest(), tag):
        return None
    iv, ct = body[:16], body[16:]
    dec = Cipher(algorithms.AES(ek), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = sympad.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def main() -> int:
    print(f"RNS {RNS.__version__}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)

    cfg = Path(tempfile.mkdtemp(prefix="retinue-channel-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[cli]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {PORT}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    identity = RNS.Identity.from_bytes(SEED)

    sent = {"done": False}

    def on_link(link):
        def push():
            # Wait until the channel is ready (needs an RTT), then send one message.
            for _ in range(60):
                try:
                    ch = link.get_channel()
                    ch.register_message_type(ProbeMessage)
                    if ch.is_ready_to_send():
                        ch.send(ProbeMessage(CHANNEL_PAYLOAD))
                        sent["done"] = True
                        print("RNS sent a channel message")
                        return
                except Exception as ex:
                    print("channel not ready:", type(ex).__name__, ex)
                time.sleep(0.1)
            print("channel never became ready")
        threading.Thread(target=push, daemon=True).start()

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

    # Link handshake (we are the initiator, fixed ephemeral seed).
    req_payload = EPH_X_PUB + EPH_ED_PUB + bytes([0x20, 0x01, 0xf4])
    lr = bytes([0x02, 0x00]) + dest.hash + bytes([0x00]) + req_payload
    link_id = hashlib.sha256(bytes([0x02]) + dest.hash + bytes([0x00]) + req_payload[:64]).digest()[:16]
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

    # RTT so RNS marks the link active and the channel becomes ready.
    rtt = token_encrypt(sk, ek, b"\xca" + struct.pack(">f", 0.05), bytes([0x55] * 16))
    sock.sendall(frame(bytes([0x0c, 0x00]) + link_id + bytes([0xfe]) + rtt))

    # Collect context-14 packets for a few seconds WITHOUT acking, to see retransmits.
    deadline = time.time() + 6.0
    channel_pkts: list[bytes] = []
    seen = set()
    while time.time() < deadline:
        for f in deframe(bytes(rx)):
            if len(f) >= 19 and (f[0] & 0b11) == 0 and f[2:18] == link_id and f[18] == CTX_CHANNEL:
                if f not in seen:
                    seen.add(f)
                    channel_pkts.append(f)
        time.sleep(0.1)

    if not channel_pkts:
        print("no channel packet captured"); stop.set(); RNS.exit(); return 1

    # Decrypt each captured channel packet's token -> the plaintext envelope.
    envelopes = []
    for pkt in channel_pkts:
        env = token_decrypt(sk, ek, pkt[19:])
        if env is not None:
            envelopes.append(env)
    # A retransmit shows up as the same envelope seen more than once (fresh IV each
    # time makes the ciphertext differ, so count on the decrypted plaintext).
    env_counts = Counter(e.hex() for e in envelopes)
    retransmits = {h: c for h, c in env_counts.items() if c > 1}

    first = envelopes[0] if envelopes else b""
    parsed = None
    if len(first) >= 6:
        parsed = {
            "msgtype": int.from_bytes(first[0:2], "big"),
            "sequence": int.from_bytes(first[2:4], "big"),
            "length": int.from_bytes(first[4:6], "big"),
            "payload_hex": first[6:].hex(),
        }

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "channel_link.json").write_text(json.dumps({
        "description": (
            "RNS 1.3.8 Channel over a real link. context-14 packets captured and decrypted "
            "with the derived link key. We never acknowledged; retransmit_counts shows how "
            "often each identical envelope was resent, which reveals proof-based reliability."
        ),
        "rns_version": RNS.__version__,
        "link_id_hex": link_id.hex(),
        "channel_payload": CHANNEL_PAYLOAD.decode(),
        "context": CTX_CHANNEL,
        "distinct_channel_packets": len(channel_pkts),
        "decoded_envelopes": len(envelopes),
        "first_envelope_hex": first.hex(),
        "first_envelope_parsed": parsed,
        "retransmit_counts": env_counts,
        "retransmitted_without_ack": bool(retransmits),
    }, indent=2) + "\n", encoding="utf-8")

    print(f"captured {len(channel_pkts)} distinct channel packets, decoded {len(envelopes)} envelopes")
    print(f"first envelope: {first.hex()}  parsed={parsed}")
    print(f"retransmitted-without-ack: {bool(retransmits)}  counts={dict(env_counts)}")
    stop.set(); sock.close(); RNS.exit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
