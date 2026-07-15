"""R4 multi-segment SEND gate: retinue sends a 2.5 MB resource (3 segments) to RNS.

The multi-megabyte done-condition, send direction. RNS receives it in RAM (ACCEPT_APP),
reassembles all segments, and concludes COMPLETE; retinue verifies each segment's proof.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_send_multiseg.py
"""
from __future__ import annotations
import hashlib, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEST_SEED = bytes([0x11] * 64)
done = threading.Event()
got = {}
EXPECTED = bytes(((i * 2654435761) >> 8) & 0xff for i in range(2_500_000))
EXPECTED_HASH = hashlib.sha256(EXPECTED).hexdigest()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_send_multiseg"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    def pump():
        for l in proc.stdout: l = l.rstrip(); lines.append(l); print(f"  [retinue] {l}")
    threading.Thread(target=pump, daemon=True).start()
    port = None; dl = time.time() + 200
    while time.time() < dl and port is None:
        for l in list(lines):
            m = re.match(r"LISTENING (\d+)", l)
            if m: port = int(m.group(1)); break
        if proc.poll() is not None: return 1
        time.sleep(0.2)
    if port is None: proc.kill(); return 1
    cfg = Path(tempfile.mkdtemp(prefix="retinue-ms-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
        f"    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    try:
        identity = RNS.Identity.from_bytes(DEST_SEED)
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "recv")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        def cb(resource):
            got["status"] = resource.status
            try:
                data = resource.data.read() if hasattr(resource.data, "read") else bytes(resource.data)
                got["hash"] = hashlib.sha256(data).hexdigest()
                got["len"] = len(data)
            except Exception as e:
                print("  RNS read err", e)
            print(f"  RNS: concluded status={resource.status} len={got.get('len')}")
            done.set()
        dest.set_link_established_callback(lambda l: (
            l.set_resource_strategy(RNS.Link.ACCEPT_APP),
            l.set_resource_callback(lambda r: True),
            l.set_resource_concluded_callback(cb),
        ))
        print("waiting...\n")
        done.wait(timeout=90)
        time.sleep(1)

        joined = "\n".join(lines)
        data_ok = got.get("hash") == EXPECTED_HASH
        rns_complete = got.get("status") == 6
        retinue_verified = "ALL_SEGMENTS_SENT ok=true" in joined
        seg_count = joined.count("proof_ok=true")
        print("\n" + "=" * 68)
        print(f"RNS received retinue's {len(EXPECTED)}-byte resource intact: {'PASS' if data_ok else 'FAIL'}")
        print(f"segments proved ({seg_count}):                    {'PASS' if seg_count == 3 else 'FAIL'}")
        print(f"RNS concluded COMPLETE:                    {'PASS' if rns_complete else 'FAIL'}")
        print(f"retinue verified all segment proofs:       {'PASS' if retinue_verified else 'FAIL'}")
        print("=" * 68)
        ok = data_ok and rns_complete and retinue_verified
        print(f"R4 MULTI-SEGMENT SEND INTEROP (2.5 MB): {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
