"""Pin the link key derivation by establishing a real link with a known-secret initiator.

Black box: we run RNS, we never read its source. We DO call its documented static helpers
(Link.link_id_from_lr_packet, mode_from_lr_packet, ...) to cross-check our own derivations,
and we let RNS's packet callback be the oracle: if RNS decrypts data we encrypted with our
derived key, the derivation is right.

We are the link INITIATOR, so we know our ephemeral secret; RNS's ephemeral public arrives
in the proof. That makes the ECDH computable and the whole thing verifiable.
"""
from __future__ import annotations

import hashlib
import hmac as hmaclib
import socket
import struct
import threading
import time
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad

import RNS

SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)
PORT = 42690
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20

# Our initiator's ephemeral keys, fixed for reproducibility.
EPH_X_PRIV = X25519PrivateKey.from_private_bytes(bytes([0x33] * 32))
EPH_X_PUB = EPH_X_PRIV.public_key().public_bytes_raw()
# Ed25519 for the request blob. RNS wants 64 bytes of "public key"; the initiator's
# signing half is not used to sign anything in establishment, but the blob carries it.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
EPH_ED_PRIV = Ed25519PrivateKey.from_private_bytes(bytes([0x44] * 32))
EPH_ED_PUB = EPH_ED_PRIV.public_key().public_bytes_raw()

received = {}
established = threading.Event()
got_data = threading.Event()


def frame(p: bytes) -> bytes:
    out = bytearray([FLAG])
    for b in p:
        if b in (FLAG, ESC):
            out += bytes([ESC, b ^ ESC_MASK])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def deframe(stream: bytes):
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


def link_id_formula(flags, dest, context, payload):
    material = bytes([flags & 0x0F]) + dest + bytes([context]) + payload[:64]
    return hashlib.sha256(material).digest()[:16]


def token_encrypt(sign_key, enc_key, plaintext, iv):
    padder = sympad.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    body = iv + ct
    tag = hmaclib.new(sign_key, body, hashlib.sha256).digest()
    return body + tag


def token_decrypt(sign_key, enc_key, token):
    body, tag = token[:-32], token[-32:]
    if not hmaclib.compare_digest(hmaclib.new(sign_key, body, hashlib.sha256).digest(), tag):
        raise ValueError("hmac mismatch")
    iv, ct = body[:16], body[16:]
    dec = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unp = sympad.PKCS7(128).unpadder()
    return unp.update(padded) + unp.finalize()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    # We listen; RNS dials in as a TCP client. This is the pattern the earlier captures
    # proved reliable (TCPServerInterface was racy to bind).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)

    cfg = Path(tempfile.mkdtemp(prefix="retinue-linkc-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[cli]]\n    type = TCPClientInterface\n    enabled = yes\n"
        "    target_host = 127.0.0.1\n"
        f"    target_port = {PORT}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))

    identity = RNS.Identity.from_bytes(SEED)
    rns_ed_pub = identity.get_public_key()[32:64]

    def on_link(link):
        print(f"  RNS: link ESTABLISHED, id={link.link_id.hex()}, mode={link.get_mode()}")
        received["rns_link_id"] = link.link_id.hex()
        received["rns_link"] = link

        def on_packet(message, packet):
            print(f"  RNS: link packet received: {bytes(message)!r}")
            received["rns_got"] = bytes(message)
            got_data.set()
            # Reply, to test the RNS -> initiator direction.
            RNS.Packet(link, b"hi-from-rns").send()

        link.set_packet_callback(on_packet)
        established.set()

    dest = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test"
    )
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    dest.set_link_established_callback(on_link)
    dest.accepts_links(True)
    print(f"RNS destination {dest.hash.hex()} listening on {PORT}")

    print("waiting for RNS to dial in...")
    sock = None
    accept_deadline = time.time() + 20
    while time.time() < accept_deadline:
        try:
            sock, addr = srv.accept()
            print(f"  RNS connected from {addr}")
            break
        except TimeoutError:
            continue
    if sock is None:
        print("  RNS never connected")
        RNS.exit(); return 1
    sock.settimeout(0.5)
    rx = bytearray()
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rx.extend(chunk)
            except TimeoutError:
                continue
            except OSError:
                break

    threading.Thread(target=reader, daemon=True).start()

    # --- build and send the link request
    req_payload = EPH_X_PUB + EPH_ED_PUB + bytes([0x20, 0x01, 0xf4])  # mode256, mtu500
    req_flags = 0x02  # LinkRequest, single, header1, broadcast
    lr = bytes([req_flags, 0x00]) + dest.hash + bytes([0x00]) + req_payload

    # Cross-check our link_id against RNS's own helper.
    my_link_id = link_id_formula(req_flags, dest.hash, 0x00, req_payload)
    rns_pkt = RNS.Packet(None, None)
    rns_pkt.raw = lr
    rns_pkt.unpack()
    rns_link_id = RNS.Link.link_id_from_lr_packet(rns_pkt)
    rns_mode = RNS.Link.mode_from_lr_packet(rns_pkt)
    rns_mtu = RNS.Link.mtu_from_lr_packet(rns_pkt)
    print("\nLink request cross-check (our formula vs RNS's own helpers):")
    print(f"  link_id  ours={my_link_id.hex()}  rns={rns_link_id.hex()}  "
          f"MATCH={my_link_id == rns_link_id}")
    print(f"  mode     rns={rns_mode}  (1 = AES-256-CBC)")
    print(f"  mtu      rns={rns_mtu}")

    print("\nsending link request...")
    sock.sendall(frame(lr))

    # --- wait for the proof
    proof = None
    deadline = time.time() + 6
    seen = 0
    while time.time() < deadline and proof is None:
        for f in deframe(bytes(rx)):
            if len(f) >= 19 and f[0] & 0b11 == 3:  # Proof
                proof = f
                break
        time.sleep(0.05)

    if proof is None:
        print("  no proof received")
        stop.set(); RNS.exit(); return 1

    print(f"  proof received: {len(proof)} bytes, context=0x{proof[18]:02x}")
    proof_payload = proof[19:]
    print(f"    payload {len(proof_payload)} bytes")
    signature = proof_payload[:64]
    rns_eph_x = proof_payload[64:96]
    trailer = proof_payload[96:99] if len(proof_payload) >= 99 else b""
    print(f"    signature   {signature.hex()}")
    print(f"    rns_eph_x   {rns_eph_x.hex()}")
    print(f"    trailer     {trailer.hex()}")

    # --- verify the proof signature: signed = link_id || rns_eph_x || rns_ed_pub || trailer
    signed = my_link_id + rns_eph_x + rns_ed_pub + trailer
    try:
        Ed25519PublicKey.from_public_bytes(rns_ed_pub).verify(signature, signed)
        print("    proof signature VERIFIES (signed = link_id||rns_eph_x||rns_ed_pub||trailer)")
    except Exception as e:
        print(f"    proof signature FAILED with trailer: {e}")
        signed2 = my_link_id + rns_eph_x + rns_ed_pub
        try:
            Ed25519PublicKey.from_public_bytes(rns_ed_pub).verify(signature, signed2)
            print("    proof signature VERIFIES WITHOUT trailer")
        except Exception as e2:
            print(f"    proof signature FAILED without trailer too: {e2}")

    # --- derive the session key: HKDF(salt=link_id, ikm=ECDH, info=empty)
    shared = EPH_X_PRIV.exchange(X25519PublicKey.from_public_bytes(rns_eph_x))
    print(f"\n  ecdh shared {shared.hex()}")
    derived = HKDF(algorithm=hashes.SHA256(), length=64, salt=my_link_id, info=None).derive(shared)
    sign_key, enc_key = derived[:32], derived[32:]
    print(f"  derived(64) {derived.hex()}")
    print(f"    sign_key {sign_key.hex()}")
    print(f"    enc_key  {enc_key.hex()}")

    # --- send RTT (RNS marks the link active once it processes this)
    rtt_plain = b"\xca" + struct.pack(">f", 0.05)  # msgpack float32
    rtt_token = token_encrypt(sign_key, enc_key, rtt_plain, bytes([0x55] * 16))
    rtt_pkt = bytes([0x0c, 0x00]) + my_link_id + bytes([0xfe]) + rtt_token  # Data/Link, LRRTT
    print("\nsending RTT packet...")
    sock.sendall(frame(rtt_pkt))
    time.sleep(0.5)

    # --- send an encrypted data packet; RNS's callback is the oracle
    data_token = token_encrypt(sign_key, enc_key, b"hello-link", bytes([0x66] * 16))
    data_pkt = bytes([0x0c, 0x00]) + my_link_id + bytes([0x00]) + data_token  # Data/Link, ctx 0
    print("sending encrypted data packet 'hello-link'...")
    sock.sendall(frame(data_pkt))

    established.wait(timeout=5)
    got_data.wait(timeout=5)
    time.sleep(1.0)

    # --- did RNS reply? decrypt it, testing the other direction.
    reply_ok = False
    for f in deframe(bytes(rx)):
        if len(f) >= 19 and (f[0] & 0b11) == 0 and f[2:18] == my_link_id and f[18] == 0x00:
            token = f[19:]
            if token == data_token:
                continue  # our own echo in the buffer, skip
            try:
                pt = token_decrypt(sign_key, enc_key, token)
                if pt:
                    print(f"\n  decrypted an RNS link packet: {pt!r}")
                    if b"hi-from-rns" in pt:
                        reply_ok = True
            except Exception:
                pass

    print("\n" + "=" * 68)
    print(f"link_id cross-check:        {'PASS' if my_link_id == rns_link_id else 'FAIL'}")
    print(f"RNS established the link:   {'PASS' if established.is_set() else 'FAIL'}")
    print(f"RNS decrypted our data:     {'PASS' if received.get('rns_got') == b'hello-link' else 'FAIL'}"
          f"  (got {received.get('rns_got')!r})")
    print(f"we decrypted RNS's reply:   {'PASS' if reply_ok else 'FAIL'}")
    print("=" * 68)
    ok = (my_link_id == rns_link_id and established.is_set()
          and received.get("rns_got") == b"hello-link" and reply_ok)
    print(f"LINK CRYPTO: {'ALL PASS' if ok else 'INCOMPLETE'}")

    stop.set()
    sock.close()
    RNS.exit()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
