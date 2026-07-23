"""R2 gate: retinue path-request + address book against a transport-enabled RNS.

RNS runs as a transport node hosting a target destination. retinue connects, announces
itself, requests a path to the target, and resolves it once RNS relays the target's
announce. Exercises retinue's path-request wire format and address-book ingestion against
real RNS transport behaviour.

Local gate. Same black-box discipline.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_r2.py
"""

from __future__ import annotations

import atexit
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
TARGET_SEED = bytes([0x44] * 64)  # matches TARGET_SEED in the Rust example


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "r2_pathfind"],
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

    cfg = Path(tempfile.mkdtemp(prefix="retinue-r2-"))
    # enable_transport = Yes makes this a transport node that answers path requests.
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 4\n\n[interfaces]\n"
        "  [[retinue]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {port}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    exit_code = 1
    try:
        # Host the target destination this transport node knows about.
        target_identity = RNS.Identity.from_bytes(TARGET_SEED)
        target = RNS.Destination(target_identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                                 "retinue", "target")
        print(f"RNS transport node hosting target {target.hash.hex()}")

        # Announce the target periodically; the transport node also answers path requests
        # for it. Either way retinue should ingest the announce and resolve the target.
        def announcer():
            for _ in range(12):
                target.announce()
                time.sleep(1.5)
        threading.Thread(target=announcer, daemon=True).start()

        dl = time.time() + 30
        while time.time() < dl and "DONE" not in "\n".join(lines):
            time.sleep(0.2)
        time.sleep(0.5)

        joined = "\n".join(lines)
        print("\n" + "=" * 68)
        announced_self = "ANNOUNCED_SELF" in joined
        sent_request = "SENT_PATH_REQUEST" in joined
        re_announced = "RE_ANNOUNCED" in joined
        resolved = "RESOLVED_TARGET" in joined
        print(f"retinue announced itself:       {'PASS' if announced_self else 'FAIL'}")
        print(f"retinue re-announced (cadence): {'PASS' if re_announced else 'FAIL'}")
        print(f"retinue sent a path request:    {'PASS' if sent_request else 'FAIL'}")
        print(f"retinue resolved the target:    {'PASS' if resolved else 'FAIL'}")
        print("=" * 68)
        ok = announced_self and sent_request and resolved
        print(f"R2 INTEROP: {'PASS' if ok else 'FAIL'}")
        exit_code = 0 if ok else 1
        return exit_code
    finally:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        atexit.register(shutil.rmtree, cfg, ignore_errors=True)
        RNS.exit(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
