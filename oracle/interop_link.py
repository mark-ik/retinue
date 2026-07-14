"""R3 live link gate: retinue establishes an encrypted link with RNS 1.3.8, both ways.

The R3 done-condition. retinue (the Rust example link_interop) is the initiator; a real RNS
is the responder. Proves, over a live TCP connection:

  1. retinue -> RNS. RNS decrypts application bytes retinue encrypted on the link.
  2. RNS -> retinue. retinue decrypts application bytes RNS encrypted back.
  3. The link survives an idle period and still carries data.

Local gate, needs Python. CI uses the committed link_session fixtures instead.

Same black-box discipline: we run RNS, we never read its source.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u interop_link.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SEED = bytes.fromhex("f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2)

rns_received: list[bytes] = []
established = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "link_interop"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    lines: list[str] = []

    def pump():
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            lines.append(line)
            print(f"  [retinue] {line}")
    threading.Thread(target=pump, daemon=True).start()

    port = None
    deadline = time.time() + 180
    while time.time() < deadline and port is None:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1)); break
        if proc.poll() is not None:
            print("probe exited early", file=sys.stderr); return 1
        time.sleep(0.2)
    if port is None:
        proc.kill(); return 1

    cfg = Path(tempfile.mkdtemp(prefix="retinue-linki-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[retinue]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {port}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    try:
        identity = RNS.Identity.from_bytes(SEED)

        def on_link(link):
            def on_packet(message, packet):
                msg = bytes(message)
                rns_received.append(msg)
                print(f"  RNS: received {msg!r} on the link")
                RNS.Packet(link, b"pong-from-rns").send()
            link.set_packet_callback(on_packet)
            established.set()
            print("  RNS: link established")

        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.set_link_established_callback(on_link)
        dest.accepts_links(True)
        print(f"RNS destination {dest.hash.hex()}\n")

        # Let the whole exchange play out (retinue idles ~4s near the end).
        deadline = time.time() + 40
        while time.time() < deadline and "DONE" not in lines:
            time.sleep(0.3)
        time.sleep(0.5)

        joined = "\n".join(lines)
        print("\n" + "=" * 68)
        rns_decrypted = b"hello-over-the-link" in rns_received
        idle_survived = b"after-idle" in rns_received
        retinue_decrypted = "RECV_DATA pong-from-rns" in joined
        established_ok = established.is_set() and "LINK_ESTABLISHED" in joined

        print(f"link established (both sides):  {'PASS' if established_ok else 'FAIL'}")
        print(f"retinue -> RNS decrypt:         {'PASS' if rns_decrypted else 'FAIL'}")
        print(f"RNS -> retinue decrypt:         {'PASS' if retinue_decrypted else 'FAIL'}")
        print(f"link survived idle:             {'PASS' if idle_survived else 'FAIL'}")
        print("=" * 68)
        ok = established_ok and rns_decrypted and retinue_decrypted and idle_survived
        print(f"R3 LINK INTEROP: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        RNS.exit()
        shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
