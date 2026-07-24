"""R1 live interop gate: retinue and RNS 1.4.0 over a real TCP connection, both ways.

This is the R1 done-condition. It is a LOCAL gate, not a CI test: it needs the Python
oracle. CI replays the committed fixtures instead and needs no Python.

What it proves:

  1. retinue -> RNS. retinue builds and frames an announce, puts it on a TCP socket, and a
     real RNS accepts it: signature valid, identity recovered, app_data intact.
  2. RNS -> retinue. RNS announces over the same connection, and retinue de-frames,
     decodes and validates it.

Either direction failing means we are not wire-compatible, whatever the unit tests say.

Same black-box discipline: we run RNS, we never read its source.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u interop_r1.py
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

ORACLE_SEED = bytes.fromhex(
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2
)

# What retinue announces. Must match examples/interop_tcp.rs.
RETINUE_ASPECT = "retinue.interop"
RETINUE_APP_DATA = b"hello-from-retinue"

got_retinue_announce: dict = {}
announce_seen = threading.Event()


class RetinueAnnounceHandler:
    """RNS calls this when it accepts an announce. Reaching it at all means the announce
    passed RNS's own signature validation."""

    aspect_filter = RETINUE_ASPECT

    def received_announce(self, destination_hash, announced_identity, app_data):
        got_retinue_announce.update(
            destination_hash=destination_hash.hex(),
            identity_hash=announced_identity.hash.hex(),
            app_data=bytes(app_data) if app_data else b"",
        )
        announce_seen.set()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    # --- start retinue, and learn the port it bound.
    print("starting retinue (cargo run --example interop_tcp)...")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "interop_tcp"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    lines: list[str] = []

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            lines.append(line)
            print(f"  [retinue] {line}")

    threading.Thread(target=pump, daemon=True).start()

    port = None
    deadline = time.time() + 120  # cargo may need to build
    while time.time() < deadline:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1))
                break
        if port:
            break
        if proc.poll() is not None:
            print("retinue exited before it listened", file=sys.stderr)
            return 1
        time.sleep(0.2)

    if port is None:
        print("timed out waiting for retinue to listen", file=sys.stderr)
        proc.kill()
        return 1
    print(f"retinue is listening on {port}\n")

    # --- point a real RNS TCP interface at it.
    cfgdir = Path(tempfile.mkdtemp(prefix="retinue-interop-"))
    (cfgdir / "config").write_text(
        "[reticulum]\n"
        "  enable_transport = No\n"
        "  share_instance = No\n"
        "  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 3\n"
        "\n[interfaces]\n"
        "  [[retinue]]\n"
        "    type = TCPClientInterface\n"
        "    enabled = yes\n"
        "    target_host = 127.0.0.1\n"
        f"    target_port = {port}\n",
        encoding="utf-8",
    )

    RNS.Reticulum(configdir=str(cfgdir))
    exit_code = 1
    try:
        RNS.Transport.register_announce_handler(RetinueAnnounceHandler())

        identity = RNS.Identity.from_bytes(ORACLE_SEED)
        dest = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test"
        )
        print(f"RNS destination {dest.hash.hex()}")

        time.sleep(2.5)  # let the TCP interface connect

        print("\nRNS announcing...")
        dest.announce(app_data=b"hello-from-rns")

        # Wait for retinue's announce to come back through RNS's own validation.
        announce_seen.wait(timeout=15)
        time.sleep(1.0)

        # --- verdict
        print("\n" + "=" * 68)
        joined = "\n".join(lines)

        # Direction 1: RNS accepted retinue's announce.
        rns_accepted = bool(got_retinue_announce)
        print("retinue -> RNS")
        if rns_accepted:
            print(f"  RNS ACCEPTED retinue's announce")
            print(f"    destination {got_retinue_announce['destination_hash']}")
            print(f"    identity    {got_retinue_announce['identity_hash']}")
            print(f"    app_data    {got_retinue_announce['app_data']!r}")
            if got_retinue_announce["app_data"] != RETINUE_APP_DATA:
                print(f"    !! app_data mismatch, wanted {RETINUE_APP_DATA!r}")
                rns_accepted = False
        else:
            print("  RNS never accepted an announce from retinue")

        # Direction 2: retinue validated RNS's announce.
        retinue_accepted = "VALIDATED_RNS_ANNOUNCE" in joined
        rejected = "REJECTED_RNS_ANNOUNCE" in joined
        print("RNS -> retinue")
        if retinue_accepted:
            print("  retinue VALIDATED RNS's announce")
        elif rejected:
            print("  retinue REJECTED RNS's announce (we are not wire-compatible)")
        else:
            print("  retinue never received an announce from RNS")

        ok = rns_accepted and retinue_accepted
        print("=" * 68)
        print(f"R1 INTEROP: {'PASS' if ok else 'FAIL'}")
        exit_code = 0 if ok else 1
        return exit_code
    finally:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        atexit.register(shutil.rmtree, cfgdir, ignore_errors=True)
        RNS.exit(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
