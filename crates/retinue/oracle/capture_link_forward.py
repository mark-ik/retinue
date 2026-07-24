"""Can a retinue link traverse an RNS transport node? (R7 packet forwarding + link transport)

Topology:  retinue-initiator  <->  RNS(enable_transport, TCPServer)  <->  retinue-responder

The responder announces a destination; RNS forwards the announce to the initiator; the
initiator opens a link to it. If RNS forwards the link request to the responder and the
proof back to the initiator (link transport), the link establishes and the echo returns.
This tells us whether retinue's header-type-1 link is forwardable as-is.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u capture_link_forward.py
"""
from __future__ import annotations
import os, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def run_peer(role, addr, sink):
    env = dict(os.environ, RETINUE_ROLE=role, RETINUE_ADDR=addr)
    p = subprocess.Popen(["cargo", "run", "--quiet", "--example", "link_peer"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    def pump():
        for line in p.stdout:
            sink.append((role, line.rstrip()))
            print(f"  [{role}] {line.rstrip()}")
    threading.Thread(target=pump, daemon=True).start()
    return p


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    port = 46010
    cfg = Path(tempfile.mkdtemp(prefix="retinue-fwd-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 4\n"
        "\n[interfaces]\n  [[srv]]\n    type = TCPServerInterface\n    enabled = yes\n"
        f"    listen_ip = 127.0.0.1\n    listen_port = {port}\n",
        encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    print(f"RNS transport node on {port}\n")
    time.sleep(1.0)

    sink = []
    resp = run_peer("responder", f"127.0.0.1:{port}", sink)
    time.sleep(2.0)  # let the responder announce and RNS learn the path
    init = run_peer("initiator", f"127.0.0.1:{port}", sink)

    time.sleep(20)
    for p in (resp, init):
        try: p.wait(timeout=3)
        except Exception: p.kill()

    joined = [l for _, l in sink]
    linked = any("LINKED" in l for l in joined)
    echo = any("ECHO_OK" in l for l in joined)
    resolved = any("RESOLVED_RESPONDER" in l for l in joined)
    print("\n" + "=" * 68)
    print(f"initiator learned responder via forwarded announce: {resolved}")
    print(f"link established through the transport node:         {linked}")
    print(f"echo returned through the transport node:            {echo}")
    print("=" * 68)
    print(f"R7 LINK-THROUGH-TRANSPORT: {'PASS' if (linked and echo) else 'FAIL (needs header-type-2 forwarding)'}")
    RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
