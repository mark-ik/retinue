"""Observe how an RNS transport node propagates announces between two interfaces.

Topology:  retinue-A  <-TCP->  RNS(enable_transport=Yes, TCPServer)  <-TCP->  retinue-B

Both retinue announce loggers connect to the RNS transport node. If RNS forwards announces
between its client interfaces, A sees B's announce (and vice versa) with hops incremented.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u capture_routing.py
"""
from __future__ import annotations
import os, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def run_logger(label, addr, sink):
    env = dict(os.environ, RETINUE_LABEL=label, RETINUE_ADDR=addr)
    p = subprocess.Popen(["cargo", "run", "--quiet", "--example", "announce_logger"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    def pump():
        for line in p.stdout:
            sink.append((label, line.rstrip()))
            print(f"  [{label}] {line.rstrip()}")
    threading.Thread(target=pump, daemon=True).start()
    return p


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    # RNS transport node with a TCP server the retinue loggers dial into.
    port = 45999
    cfg = Path(tempfile.mkdtemp(prefix="retinue-tn-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 4\n"
        "\n[interfaces]\n  [[srv]]\n    type = TCPServerInterface\n    enabled = yes\n"
        f"    listen_ip = 127.0.0.1\n    listen_port = {port}\n",
        encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    print(f"RNS transport node listening on {port}\n")

    sink = []
    time.sleep(1.0)
    a = run_logger("a", f"127.0.0.1:{port}", sink)
    b = run_logger("b", f"127.0.0.1:{port}", sink)

    time.sleep(16)
    try:
        a.wait(timeout=3)
        b.wait(timeout=3)
    except Exception:
        a.kill(); b.kill()

    # Did A see B's announce and vice versa?
    a_dest = next((l.split()[2] for lab, l in sink if lab == "a" and l.startswith("SELF")), None)
    b_dest = next((l.split()[2] for lab, l in sink if lab == "b" and l.startswith("SELF")), None)
    a_saw_b = any(lab == "a" and b_dest and b_dest in l and "RECV_ANNOUNCE" in l for lab, l in sink)
    b_saw_a = any(lab == "b" and a_dest and a_dest in l and "RECV_ANNOUNCE" in l for lab, l in sink)
    hops = [l for lab, l in sink if "RECV_ANNOUNCE" in l]

    print("\n" + "=" * 68)
    print(f"A dest {a_dest}  B dest {b_dest}")
    print(f"A saw B's announce (forwarded): {a_saw_b}")
    print(f"B saw A's announce (forwarded): {b_saw_a}")
    print("hops observed:")
    for h in hops[:6]:
        print("  " + h)
    print("=" * 68)
    RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
