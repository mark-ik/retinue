"""Capture RESOURCE_REQ + RESOURCE_PRF: retinue sends a resource, RNS receives it.

RNS is the receiver, so it emits the request and the proof, which retinue dumps. RNS's
resource callback firing with the correct data proves retinue's sender interoperates.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u capture_resource_send.py
"""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEST_SEED = bytes([0x11] * 64)
got = {}
done = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_send_probe"],
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

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rsend-"))
    (cfg / "storage" / "resources").mkdir(parents=True, exist_ok=True)
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=7\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
        f"    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    try:
        identity = RNS.Identity.from_bytes(DEST_SEED)
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "recv")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        def resource_cb(resource):
            print(f"  RNS: RESOURCE received status={resource.status} "
                  f"size={getattr(resource,'total_size',None)}")
            try:
                data = resource.data.read() if hasattr(resource.data, "read") else bytes(resource.data)
                got["data"] = data
                print(f"  RNS: resource data {len(data)} bytes, first16={data[:16].hex()}")
            except Exception as e:
                print(f"  RNS: read err {e}")
            done.set()
        def resource_started(resource):
            print("  RNS: resource advertised, accepting")
        dest.set_link_established_callback(lambda l: (
            l.set_resource_strategy(RNS.Link.ACCEPT_ALL),
            l.set_resource_started_callback(resource_started),
            l.set_resource_concluded_callback(resource_cb),
        ))
        print(f"RNS receiver {dest.hash.hex()}\n")

        done.wait(timeout=30)
        time.sleep(1)
        expected = bytes(((i * 7 + 3) & 0xff) for i in range(300))
        ok = got.get("data") == expected
        print("\n" + "=" * 68)
        print(f"RNS received retinue's resource intact: {'PASS' if ok else 'FAIL'}")
        if got.get("data") is not None and not ok:
            print(f"  got {len(got['data'])} bytes, expected {len(expected)}")
        print("=" * 68)
        return 0 if ok else 1
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
