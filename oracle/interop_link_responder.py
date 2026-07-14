"""R3 responder gate: RNS 1.3.8 initiates an encrypted link TO retinue.

The mirror of interop_link.py. retinue is the responder: it announces, RNS links to it,
retinue proves and accepts, and they exchange encrypted bytes. Proves:

  1. RNS -> retinue. retinue decrypts data RNS encrypted on the link retinue proved.
  2. retinue -> RNS. RNS decrypts retinue's encrypted echo (so retinue's proof-derived key
     is the one RNS also derived).
  3. A keepalive round-trip.

Local gate, needs Python. Same black-box discipline.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u interop_link_responder.py
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

retinue_dest_aspect = "retinue.responder"
rns_got: list[bytes] = []
link_up = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "link_responder"],
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

    cfg = Path(tempfile.mkdtemp(prefix="retinue-linkr-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[retinue]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {port}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    try:
        state = {}

        class LinkToRetinue:
            aspect_filter = retinue_dest_aspect

            def received_announce(self, destination_hash, announced_identity, app_data):
                if "link" in state:
                    return
                print(f"  RNS: saw retinue announce {destination_hash.hex()}, linking...")
                out = RNS.Destination(
                    announced_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                    "retinue", "responder",
                )
                link = RNS.Link(out)
                state["link"] = link

                def on_established(l):
                    print("  RNS: link to retinue ESTABLISHED")
                    link_up.set()

                    def on_packet(message, packet):
                        rns_got.append(bytes(message))
                        print(f"  RNS: received {bytes(message)!r} on the link")
                    l.set_packet_callback(on_packet)
                    # Send data for retinue to decrypt and echo.
                    RNS.Packet(l, b"hello-responder").send()

                link.set_link_established_callback(on_established)

        RNS.Transport.register_announce_handler(LinkToRetinue())
        print("waiting for retinue's announce...\n")

        # Wait for establishment, then drive a keepalive and let echoes flow.
        for _ in range(200):
            if link_up.is_set():
                break
            time.sleep(0.1)

        time.sleep(3.0)
        link = state.get("link")
        if link is not None and link.status == RNS.Link.ACTIVE:
            print("  RNS: sending keepalive...")
            link.send_keepalive()
            time.sleep(2.0)
            print("  RNS: closing link...")
            link.teardown()
            time.sleep(1.0)

        # Wait for retinue to finish.
        for _ in range(60):
            if "DONE" in lines:
                break
            time.sleep(0.2)

        joined = "\n".join(lines)
        print("\n" + "=" * 68)
        proved = "LINK_ACCEPTED" in joined and "SENT_PROOF" in joined
        rns_est = link_up.is_set()
        retinue_decrypted = "RECV_DATA hello-responder" in joined
        rns_decrypted_echo = any(b"echo:hello-responder" == m for m in rns_got)
        keepalive = "RECV_KEEPALIVE_REQUEST" in joined and "SENT_KEEPALIVE_RESPONSE" in joined

        print(f"retinue proved the link:        {'PASS' if proved else 'FAIL'}")
        print(f"RNS established (link active):  {'PASS' if rns_est else 'FAIL'}")
        print(f"retinue decrypted RNS data:     {'PASS' if retinue_decrypted else 'FAIL'}")
        print(f"RNS decrypted retinue's echo:   {'PASS' if rns_decrypted_echo else 'FAIL'}")
        print(f"keepalive round-trip:           {'PASS' if keepalive else 'FAIL'}")
        print("=" * 68)
        ok = proved and rns_est and retinue_decrypted and rns_decrypted_echo and keepalive
        print(f"R3 RESPONDER INTEROP: {'PASS' if ok else 'FAIL'}")
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
