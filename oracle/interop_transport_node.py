"""Can a real RNS node route through a retinue transport node?

Topology:  RNS-leaf  <->  retinue transport node (routing)  <->  retinue-responder

The retinue responder announces a destination; the retinue transport node forwards the
announce to the RNS leaf (header-type-2, stamped with the node's id). RNS learns the
destination via the retinue node and opens a link to it. If the retinue node forwards RNS's
link request to the responder and the proof + data back, retinue is a working transport node
in a real RNS mesh.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_transport_node.py
"""
from __future__ import annotations
import os, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
HUB_PORT = 46030
# The retinue responder's fixed identity (RESPONDER_SEED in examples/link_peer.rs).
RESPONDER_SEED = bytes([0x42] * 64)
got = {}
done = threading.Event()


def spawn(example, env_extra, sink, label):
    env = dict(os.environ, **env_extra)
    p = subprocess.Popen(["cargo", "run", "--quiet", "--example", example],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    def pump():
        for line in p.stdout:
            sink.append(line.rstrip()); print(f"  [{label}] {line.rstrip()}")
    threading.Thread(target=pump, daemon=True).start()
    return p


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    sink = []
    # 1. retinue transport node.
    hub = spawn("transport_node", {"RETINUE_PORT": str(HUB_PORT)}, sink, "hub")
    deadline = time.time() + 120
    while time.time() < deadline and not any("TRANSPORT_NODE_UP" in l for l in sink):
        if hub.poll() is not None:
            print("hub exited"); return 1
        time.sleep(0.3)
    time.sleep(0.5)
    # 2. retinue responder behind the hub.
    resp = spawn("link_peer", {"RETINUE_ROLE": "responder", "RETINUE_ADDR": f"127.0.0.1:{HUB_PORT}"},
                 sink, "resp")
    time.sleep(2.0)

    # 3. RNS leaf: connect to the retinue hub, learn the responder, open a link, send data.
    cfg = Path(tempfile.mkdtemp(prefix="retinue-rnsleaf-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n  panic_on_interface_error = No\n"
        f"\n[logging]\n  loglevel = 4\n\n[interfaces]\n  [[hub]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {HUB_PORT}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))

    class Reach:
        aspect_filter = "retinue.peer"
        def received_announce(self, destination_hash, announced_identity, app_data):
            if "link" in got:
                return
            got["link"] = True
            print(f"  RNS: learned responder {destination_hash.hex()} via the retinue node; linking")
            out = RNS.Destination(announced_identity, RNS.Destination.OUT,
                                  RNS.Destination.SINGLE, "retinue", "peer")
            link = RNS.Link(out)
            def est(l):
                print("  RNS: link ESTABLISHED through the retinue transport node")
                def on_packet(message, packet):
                    got["echo"] = bytes(message)
                    print(f"  RNS: received {bytes(message)!r}")
                    done.set()
                l.set_packet_callback(on_packet)
                RNS.Packet(l, b"ping-rns").send()
            link.set_link_established_callback(est)
    RNS.Transport.register_announce_handler(Reach())
    print("RNS leaf waiting to learn the responder through the retinue node...\n")

    done.wait(timeout=25)
    time.sleep(1)
    for p in (resp, hub):
        try: p.kill()
        except Exception: pass

    linked = "link" in got
    echo_ok = got.get("echo") == b"echo:ping-rns"
    print("\n" + "=" * 68)
    print(f"RNS learned the responder via the retinue node: {linked}")
    print(f"RNS link + echo through the retinue node:       {echo_ok}")
    print("=" * 68)
    print(f"R7 RNS-ROUTES-THROUGH-RETINUE: {'PASS' if (linked and echo_ok) else 'FAIL'}")
    RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)
    return 0 if (linked and echo_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
