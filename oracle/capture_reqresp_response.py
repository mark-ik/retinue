"""Capture the response wire format: retinue sends a real request to an RNS handler.

RNS is the responder with a request handler at /echo; retinue (reqresp_init_probe) links to
it, sends a request, and prints the decrypted response. We decode both with RNS's umsgpack.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u capture_reqresp_response.py
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
SEED = bytes([0x11] * 64)  # matches DEST_SEED in the Rust probe

RESPONSE_DATA = b"pong-response-42"


def echo_handler(path, data, request_id, link_id, remote_identity, requested_at):
    print(f"  RNS handler: path={path!r} data={bytes(data)!r} request_id={bytes(request_id).hex()} "
          f"-> {RESPONSE_DATA!r}")
    return RESPONSE_DATA


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "reqresp_init_probe"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    lines = []

    def pump():
        for line in proc.stdout:
            line = line.rstrip(); lines.append(line); print(f"  [retinue] {line}")
    threading.Thread(target=pump, daemon=True).start()

    port = None
    dl = time.time() + 180
    while time.time() < dl and port is None:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1)); break
        if proc.poll() is not None:
            return 1
        time.sleep(0.2)
    if port is None:
        proc.kill(); return 1

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rrr-"))
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
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                               "retinue", "reqresp")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        dest.register_request_handler("/echo", response_generator=echo_handler,
                                      allow=RNS.Destination.ALLOW_ALL)
        print(f"RNS responder {dest.hash.hex()} with handler /echo\n")

        dl = time.time() + 30
        while time.time() < dl and "DONE" not in lines:
            time.sleep(0.2)
        time.sleep(0.5)

        joined = "\n".join(lines)
        print("\n" + "=" * 68)
        for label, pat in [("REQUEST", r"REQUEST_SENT ([0-9a-f]+)"),
                           ("RESPONSE", r"RESPONSE_PLAINTEXT ([0-9a-f]+)")]:
            m = re.search(pat, joined)
            if not m:
                print(f"{label}: not captured"); continue
            raw = bytes.fromhex(m.group(1))
            print(f"{label} plaintext ({len(raw)} bytes): {raw.hex()}")
            try:
                from RNS.vendor import umsgpack
                u = umsgpack.unpackb(raw)
                print(f"  umsgpack: {u!r}")
                if isinstance(u, list):
                    for i, el in enumerate(u):
                        print(f"    [{i}] {type(el).__name__}: {el!r}")
            except Exception as e:
                print(f"  decode failed: {e}")
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
