"""R4 round-trip gate: RNS sends an uncompressed resource; retinue receives + proves it.

RNS is the sender (no receiver-disk quirk), retinue reassembles, verifies, and returns the
proof. RNS concluding with status COMPLETE means retinue's proof was accepted, which is the
end-to-end proof of retinue's resource receiver.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_resource_recv.py
"""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
import hashlib
done = threading.Event()
result = {}
# A large, incompressible payload: forces MANY parts (well past the 74-hash advertisement
# limit) so the windowed hashmap-update (HMU) path is exercised. auto_compress off below.
PAYLOAD = bytes(((i * 2654435761) >> 8) & 0xff for i in range(2_500_000))  # 2.5 MB -> multi-segment
PAYLOAD_HASH = hashlib.sha256(PAYLOAD).hexdigest()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_recv"],
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

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rrecv-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=7\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
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
                    print("  RNS: link up, sending a 120KB UNCOMPRESSED resource (259 parts)")
                    def cb(res):
                        result["status"] = res.status
                        print(f"  RNS: resource concluded status={res.status} "
                              f"(COMPLETE=6, FAILED=7)")
                        done.set()
                    RNS.Resource(PAYLOAD, lk, callback=cb, auto_compress=False)
                link.set_link_established_callback(est)
        RNS.Transport.register_announce_handler(Linker())
        print("waiting...\n")
        done.wait(timeout=30)
        time.sleep(1)

        joined = "\n".join(lines)
        m = re.search(r"DATA_HASH ([0-9a-f]+)", joined)
        retinue_data_ok = bool(m and m.group(1) == PAYLOAD_HASH)
        used_hmu = "HMU +" in joined
        rns_complete = result.get("status") == 6  # RNS.Resource.COMPLETE
        print("\n" + "=" * 68)
        print(f"retinue reassembled the {len(PAYLOAD)}-byte payload intact: {'PASS' if retinue_data_ok else 'FAIL'}")
        print(f"windowed HMU path exercised:            {'PASS' if used_hmu else 'FAIL'}")
        print(f"RNS accepted retinue's proof (COMPLETE): {'PASS' if rns_complete else 'FAIL'}")
        print("=" * 68)
        ok = retinue_data_ok and rns_complete and used_hmu
        print(f"R4 WINDOWED RESOURCE RECEIVE INTEROP: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
