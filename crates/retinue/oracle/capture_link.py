"""Capture a live link handshake from RNS 1.3.8. Settles the two R3 unknowns.

Same black-box discipline: we run RNS, we never read its source.

The unknowns, either of which silently breaks every link if guessed wrong:

  1. Does a link request carry 64 bytes (two public keys) or 67 (plus a 3-byte mode/MTU
     trailer)? `Link.LINK_MTU_SIZE = 3` and both `MODE_AES128_CBC` and `MODE_AES256_CBC`
     exist, so the AES mode is negotiated, not fixed.
  2. Is the link id the truncated hash of the whole request payload, or only of the 64
     bytes of keys? Beechat truncates to 64 before hashing, which would discard a trailer.

Both halves are captured without retinue implementing links at all:

  - retinue announces, RNS learns it and links TO retinue  -> we see the REQUEST.
  - retinue fires a raw link request AT RNS                -> RNS answers -> we see the
    PROOF, and the address RNS puts on it IS the link id, which decides (2).

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_link.py
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

ORACLE_SEED = bytes.fromhex(
    "f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c" * 2
)

linked = threading.Event()
state: dict = {}


class LinkToRetinue:
    """When retinue announces, link to it. That makes RNS emit a link request, which is
    the packet we need to see."""

    aspect_filter = "retinue.interop"

    def received_announce(self, destination_hash, announced_identity, app_data):
        if "linked" in state:
            return
        state["linked"] = True
        print(f"\n  RNS accepted retinue's announce ({destination_hash.hex()})")
        print("  RNS is now linking to retinue, which emits a LINK REQUEST...")
        out = RNS.Destination(
            announced_identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "retinue",
            "interop",
        )
        link = RNS.Link(out)
        state["link"] = link
        linked.set()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")

    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "link_probe"],
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
    deadline = time.time() + 180
    while time.time() < deadline and port is None:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1))
                break
        if proc.poll() is not None:
            print("probe exited early", file=sys.stderr)
            return 1
        time.sleep(0.2)
    if port is None:
        proc.kill()
        return 1

    cfgdir = Path(tempfile.mkdtemp(prefix="retinue-link-"))
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
    try:
        identity = RNS.Identity.from_bytes(ORACLE_SEED)
        dest = RNS.Destination(
            identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "test"
        )
        # Answer inbound link requests, so retinue's raw request draws a proof out of RNS.
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        print(f"RNS destination {dest.hash.hex()} (proving all, accepting links)")

        RNS.Transport.register_announce_handler(LinkToRetinue())

        time.sleep(2.5)
        linked.wait(timeout=15)
        time.sleep(8)

        link = state.get("link")
        if link is not None:
            print(f"\n  RNS link id     {link.link_id.hex()}")
            print(f"  RNS link status {link.status}")
            state["link_id"] = link.link_id.hex()

        print("\n" + "=" * 68)
        print("Read the [retinue] PACKET lines above. What to look for:")
        print("  - the LINK REQUEST payload length: 64 means no trailer, >64 means there is")
        print("  - the PROOF's destination: it IS the link id, so it decides the derivation")
        print("  - the PROOF payload length: 96 = sig+key, 99 = sig+key+trailer")
        if "link_id" in state:
            print(f"\n  RNS's own link_id for the link it opened TO retinue: {state['link_id']}")
            print("  Compare with the two candidates retinue printed for that request.")
        print("=" * 68)
        return 0
    finally:
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        RNS.exit()
        shutil.rmtree(cfgdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
