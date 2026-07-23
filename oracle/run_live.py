"""Run the complete mixed-runtime Retinue/RNS interoperability matrix.

Each gate runs in its own process because RNS owns process-global state and exits the
interpreter during teardown. The gate scripts return non-zero when their done-condition
fails, so this runner is suitable as one local release check.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
GATES = (
    "interop_r1.py",
    "interop_r2.py",
    "interop_link.py",
    "interop_link_responder.py",
    "interop_reqresp.py",
    "interop_endpoint_stream.py",
    "interop_resource_recv.py",
    "interop_resource_send.py",
    "interop_send_large.py",
    "interop_send_multiseg.py",
    "interop_transport_node.py",
)


def main() -> int:
    failed: list[str] = []
    for gate in GATES:
        print(f"\n{'=' * 72}\nGATE {gate}\n{'=' * 72}", flush=True)
        completed = subprocess.run(
            [sys.executable, "-u", str(HERE / gate)],
            cwd=HERE,
            check=False,
        )
        if completed.returncode != 0:
            failed.append(gate)

    print("\n" + "=" * 72)
    if failed:
        print(f"LIVE INTEROP: FAIL ({', '.join(failed)})")
        return 1
    print(f"LIVE INTEROP: PASS ({len(GATES)} gates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
