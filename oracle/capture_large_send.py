"""Capture how RNS (receiver) solicits RESOURCE_HMU when the advert's hashmap runs out."""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEST_SEED = bytes([0x11] * 64)
done = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_large_send"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    def pump():
        for l in proc.stdout: l = l.rstrip(); lines.append(l); print(f"  [retinue] {l}")
    threading.Thread(target=pump, daemon=True).start()
    port = None; dl = time.time() + 180
    while time.time() < dl and port is None:
        for l in list(lines):
            m = re.match(r"LISTENING (\d+)", l)
            if m: port = int(m.group(1)); break
        if proc.poll() is not None: return 1
        time.sleep(0.2)
    if port is None: proc.kill(); return 1
    cfg = Path(tempfile.mkdtemp(prefix="retinue-lg-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=4\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
        f"    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    try:
        identity = RNS.Identity.from_bytes(DEST_SEED)
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "recv")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        def cb(resource):
            print(f"  RNS: concluded status={resource.status}")
            done.set()
        dest.set_link_established_callback(lambda l: (
            l.set_resource_strategy(RNS.Link.ACCEPT_APP),
            l.set_resource_callback(lambda r: True),
            l.set_resource_concluded_callback(cb),
        ))
        print("waiting...\n")
        done.wait(timeout=30)
        time.sleep(1)
        return 0
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
