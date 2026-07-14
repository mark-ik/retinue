"""Capture the TCP interface framing from RNS 1.3.8.

Same black-box discipline as capture.py: we run RNS, we never read its source.

Method: stand up a plain TCP server on loopback that speaks nothing and records every byte
it receives, then point an RNS `TCPClientInterface` at it and make RNS announce. What lands
in the recorder is exactly what RNS puts on a TCP wire, framing included.

The point of capturing before writing any framing code: Beechat has now been wrong twice
about things only capture could settle, so its `iface/hdlc.rs` gets no benefit of the doubt
either. This script states the HDLC hypothesis and then tries to falsify it.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_tcp.py
"""

from __future__ import annotations

import json
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import RNS

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

PORT = 42671
SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)

# The hypothesis under test: HDLC framing, as Beechat believes it to be.
FLAG, ESC, ESC_MASK = 0x7E, 0x7D, 0x20

recorded = bytearray()
stop = threading.Event()


def recorder() -> None:
    """A TCP server that never speaks. It only listens and records."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(1)
    srv.settimeout(1.0)
    print(f"  recorder listening on 127.0.0.1:{PORT}", flush=True)

    conn = None
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
            print(f"  RNS connected from {addr}", flush=True)
            break
        except TimeoutError:
            continue
    if conn is None:
        srv.close()
        return

    conn.settimeout(0.5)
    while not stop.is_set():
        try:
            chunk = conn.recv(65536)
            if not chunk:
                break
            recorded.extend(chunk)
        except TimeoutError:
            continue
        except OSError:
            break
    conn.close()
    srv.close()


def hdlc_deframe(stream: bytes) -> list[bytes]:
    """Split on the flag byte and un-escape. Returns the payloads between flags."""
    frames: list[bytes] = []
    cur = bytearray()
    in_frame = False
    escaped = False
    for b in stream:
        if b == FLAG:
            if in_frame and cur:
                frames.append(bytes(cur))
            cur = bytearray()
            in_frame = True
            escaped = False
            continue
        if not in_frame:
            continue
        if escaped:
            cur.append(b ^ ESC_MASK)
            escaped = False
        elif b == ESC:
            escaped = True
        else:
            cur.append(b)
    return frames


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    threading.Thread(target=recorder, daemon=True).start()
    time.sleep(0.3)

    cfgdir = Path(tempfile.mkdtemp(prefix="retinue-tcp-"))
    (cfgdir / "config").write_text(
        "[reticulum]\n"
        "  enable_transport = No\n"
        "  share_instance = No\n"
        "  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 3\n"
        "\n[interfaces]\n"
        "  [[Recorder]]\n"
        "    type = TCPClientInterface\n"
        "    enabled = yes\n"
        "    target_host = 127.0.0.1\n"
        f"    target_port = {PORT}\n",
        encoding="utf-8",
    )

    print("starting RNS with a TCPClientInterface pointed at the recorder...")
    RNS.Reticulum(configdir=str(cfgdir))
    try:
        identity = RNS.Identity.from_bytes(SEED)
        dest = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test"
        )
        print(f"destination {dest.hash.hex()}")

        time.sleep(2.0)  # let the interface connect and settle
        before = len(recorded)
        print(f"\nbytes before we announce: {before}")
        if before:
            print(f"  (preamble or interface chatter) {bytes(recorded[:before]).hex()}")

        print("\nannouncing (send=True, so it actually goes out the interface)...")
        dest.announce(app_data=b"retinue-r1-fixture")
        time.sleep(2.0)

        # Does RNS escape the ESCAPE byte too, or only the flag? The capture above only
        # proves 0x7E is escaped (the destination hash happens to contain one). app_data is
        # ours to choose, so ask RNS directly: put both special bytes in it and look.
        mark = len(recorded)
        adversarial = b"\x7e\x7d\x7e\x7d\x00\xff"
        print(f"\nannouncing again with app_data = {adversarial.hex()} "
              "(both HDLC special bytes)...")
        dest.announce(app_data=adversarial)
        time.sleep(2.0)
        tail = bytes(recorded[mark:])
        print(f"  recorded {len(tail)} more bytes")
        print(f"  {tail.hex()}")
        # The app_data is the last field of the announce payload, so it sits just before
        # the closing flag. Read the escaping straight off the tail.
        print(f"  tail before closing flag: {tail[-16:].hex()}")
        escapes_flag = b"\x7d\x5e" in tail  # 0x7e escaped
        escapes_esc = b"\x7d\x5d" in tail   # 0x7d escaped (0x5d ^ 0x20 == 0x7d)
        print(f"  escapes 0x7E as 7d5e: {escapes_flag}")
        print(f"  escapes 0x7D as 7d5d: {escapes_esc}")
        if not escapes_esc:
            print("  !! 0x7D is NOT escaped. The escape rule is flag-only.")

        stream = bytes(recorded)
        if not stream:
            print("\nFAILED: recorded nothing. Did the interface connect?")
            return 1

        print(f"\nrecorded {len(stream)} bytes")
        print(f"  {stream.hex()}")

        print("\n--- framing analysis")
        print(f"  first byte 0x{stream[0]:02x}, last byte 0x{stream[-1]:02x}")
        print(f"  flag  0x7E count: {stream.count(FLAG)}")
        print(f"  esc   0x7D count: {stream.count(ESC)}")

        frames = hdlc_deframe(stream)
        print(f"  de-framing yields {len(frames)} frame(s), lengths {[len(f) for f in frames]}")

        confirmed = False
        FIXTURES.mkdir(parents=True, exist_ok=True)
        for i, f in enumerate(frames):
            if len(f) < 19:
                print(f"    frame {i}: {len(f)} bytes (too short for a packet)")
                continue
            print(f"    frame {i}: {len(f)} bytes, flags=0x{f[0]:02x}, "
                  f"type={f[0] & 0b11}, dest={f[2:18].hex()}")
            if f[2:18] != dest.hash:
                continue
            # The real test: hand the de-framed bytes back to RNS. If our de-framing is
            # right, RNS validates its own announce out of them.
            pkt = RNS.Packet(None, None)
            pkt.raw = f
            pkt.unpack()
            valid = RNS.Identity.validate_announce(pkt)
            print(f"      -> our announce; RNS validates the de-framed bytes: {valid}")
            if not valid:
                continue
            confirmed = True
            # Keep the two announces under distinct names. The second one carries app_data
            # full of HDLC special bytes, so it is the fixture that exercises un-escaping.
            name = (
                "tcp_frame_announce_escapes.bin"
                if adversarial in f
                else "tcp_frame_announce.bin"
            )
            (FIXTURES / name).write_bytes(f)
            print(f"      wrote {name}")

        FIXTURES.mkdir(parents=True, exist_ok=True)
        (FIXTURES / "tcp_stream.bin").write_bytes(stream)
        print("\n  wrote tcp_stream.bin (raw wire stream, framing included)")

        (FIXTURES / "tcp_manifest.json").write_text(
            json.dumps(
                {
                    "rns_version": RNS.__version__,
                    "description": (
                        "Raw TCP-interface bytes from RNS 1.3.8, recorded by a socket that "
                        "speaks nothing. tcp_stream.bin is the wire stream including framing; "
                        "tcp_frame_announce.bin is one de-framed packet from it."
                    ),
                    "framing": {
                        "scheme": "HDLC" if confirmed else "UNKNOWN",
                        "flag": "0x7E",
                        "escape": "0x7D",
                        "escape_mask": "0x20 (escaped byte is XORed with 0x20)",
                        "confirmed": confirmed,
                        "escapes_flag_byte": escapes_flag,
                        "escapes_escape_byte": escapes_esc,
                        "how": (
                            "De-framed the recorded stream and handed the result back to "
                            "RNS.Identity.validate_announce, which accepted it. The escape "
                            "rules were then confirmed by announcing app_data containing both "
                            "0x7E and 0x7D and reading the escaping off the wire."
                            if confirmed
                            else "The HDLC hypothesis did NOT yield a valid packet."
                        ),
                    },
                    "stream_len": len(stream),
                    "frame_lens": [len(f) for f in frames],
                    "bytes_before_announce": before,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print("  wrote tcp_manifest.json")

        print(f"\nRESULT: HDLC framing {'CONFIRMED' if confirmed else 'NOT CONFIRMED'}")
        return 0 if confirmed else 1
    finally:
        stop.set()
        RNS.exit()
        shutil.rmtree(cfgdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
