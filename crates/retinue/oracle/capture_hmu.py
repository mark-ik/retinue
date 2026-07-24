"""Capture RESOURCE_HMU + windowing: RNS sends retinue a large (many-part) resource."""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
done = threading.Event()
# ~40 KB incompressible-ish so it stays many parts (auto_compress off).
PAYLOAD = bytes(((i * 131 + 7) & 0xff) for i in range(40000))


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_hmu_probe"],
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
    cfg = Path(tempfile.mkdtemp(prefix="retinue-hmu-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
        f"    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    try:
        class Linker:
            aspect_filter = "retinue.resource"
            def received_announce(self, destination_hash, announced_identity, app_data):
                if getattr(Linker, "x", False): return
                Linker.x = True
                out = RNS.Destination(announced_identity, RNS.Destination.OUT,
                                      RNS.Destination.SINGLE, "retinue", "resource")
                link = RNS.Link(out)
                def est(lk):
                    print(f"  RNS: sending {len(PAYLOAD)}-byte resource (auto_compress off)")
                    RNS.Resource(PAYLOAD, lk, callback=lambda r: done.set(), auto_compress=False)
                link.set_link_established_callback(est)
        RNS.Transport.register_announce_handler(Linker())
        print("waiting...\n")
        done.wait(timeout=40)
        time.sleep(1)
        return 0
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
