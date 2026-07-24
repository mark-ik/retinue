"""Capture the request/response wire format over a link from RNS 1.3.8.

retinue (reqresp_probe) is the responder; RNS links to it and sends a request. retinue
prints the DECRYPTED request plaintext, so we read RNS's msgpack packing off the wire.

Same black-box discipline. Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_reqresp.py
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

state = {}
response_seen = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "reqresp_probe"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    lines = []

    def pump():
        for line in proc.stdout:
            line = line.rstrip()
            lines.append(line)
            print(f"  [retinue] {line}")
    threading.Thread(target=pump, daemon=True).start()

    port = None
    dl = time.time() + 180
    while time.time() < dl and port is None:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1)); break
        if proc.poll() is not None:
            print("probe exited early", file=sys.stderr); return 1
        time.sleep(0.2)
    if port is None:
        proc.kill(); return 1

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rr-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[retinue]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {port}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    try:
        class Linker:
            aspect_filter = "retinue.reqresp"

            def received_announce(self, destination_hash, announced_identity, app_data):
                if "link" in state:
                    return
                print(f"  RNS: saw retinue {destination_hash.hex()}, linking + requesting...")
                out = RNS.Destination(announced_identity, RNS.Destination.OUT,
                                      RNS.Destination.SINGLE, "retinue", "reqresp")
                link = RNS.Link(out)
                state["link"] = link

                def established(l):
                    print("  RNS: link established, sending request path='/echo' data=b'ping123'")

                    def on_response(receipt):
                        print(f"  RNS: response_callback fired: {receipt.response!r}")
                        state["response"] = receipt.response
                        response_seen.set()

                    def on_failed(receipt):
                        print("  RNS: request FAILED (no/invalid response)")
                        response_seen.set()

                    l.request("/echo", data=b"ping123",
                              response_callback=on_response, failed_callback=on_failed,
                              timeout=8)

                link.set_link_established_callback(established)

        RNS.Transport.register_announce_handler(Linker())
        print("waiting for retinue announce...\n")

        response_seen.wait(timeout=25)
        time.sleep(1.0)

        # Report what we learned.
        joined = "\n".join(lines)
        m = re.search(r"REQUEST_PLAINTEXT ([0-9a-f]+)", joined)
        print("\n" + "=" * 68)
        if m:
            raw = bytes.fromhex(m.group(1))
            print(f"REQUEST plaintext ({len(raw)} bytes): {raw.hex()}")
            # Try to msgpack-decode it with RNS's own umsgpack, to name the structure.
            try:
                from RNS.vendor import umsgpack
                unpacked = umsgpack.unpackb(raw)
                print(f"  umsgpack-decoded: {unpacked!r}")
                if isinstance(unpacked, list):
                    for i, el in enumerate(unpacked):
                        print(f"    [{i}] {type(el).__name__}: {el!r}")
            except Exception as e:
                print(f"  (umsgpack decode failed: {e})")
        else:
            print("no REQUEST plaintext captured")
        print("=" * 68)
        return 0
    finally:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        RNS.exit()
        shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
