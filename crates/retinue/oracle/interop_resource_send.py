"""Capture RESOURCE_REQ + RESOURCE_PRF: retinue sends a resource, RNS receives it.

RNS is the receiver, so it emits the request and the proof, which retinue dumps. RNS's
resource callback firing with the correct data proves retinue's sender interoperates.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_resource_send.py
"""
from __future__ import annotations
import atexit, re, shutil, subprocess, sys, tempfile, threading, time
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
    exit_code = 1
    try:
        identity = RNS.Identity.from_bytes(DEST_SEED)
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "recv")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        def resource_cb(resource):
            print(f"  RNS: RESOURCE concluded status={resource.status} "
                  f"(COMPLETE=6, FAILED=7)")
            try:
                data = resource.data.read() if hasattr(resource.data, "read") else bytes(resource.data)
                got["data"] = data
                print(f"  RNS: resource data {len(data)} bytes, first16={data[:16].hex()}")
            except Exception as e:
                print(f"  RNS: read err {e}")
            got["status"] = resource.status
            done.set()
        def accept_decision(resource):
            print("  RNS: resource advertised -> accepting (ACCEPT_APP = in-RAM)")
            return True
        # ACCEPT_APP keeps the received resource in memory and delivers it to the callback,
        # avoiding RNS's on-disk assembly path (which fought the ephemeral test config).
        # set_resource_callback is the accept-decision hook (return True to accept).
        dest.set_link_established_callback(lambda l: (
            l.set_resource_strategy(RNS.Link.ACCEPT_APP),
            l.set_resource_callback(accept_decision),
            l.set_resource_concluded_callback(resource_cb),
        ))
        print(f"RNS receiver {dest.hash.hex()}\n")

        done.wait(timeout=30)
        time.sleep(1)
        expected = bytes(((i * 7 + 3) & 0xff) for i in range(300))
        joined = "\n".join(lines)
        data_ok = got.get("data") == expected
        rns_complete = got.get("status") == 6  # RNS.Resource.COMPLETE
        retinue_verified = "PROOF_VERIFIED" in joined
        print("\n" + "=" * 68)
        print(f"RNS received retinue's resource intact: {'PASS' if data_ok else 'FAIL'}")
        print(f"RNS concluded COMPLETE:                 {'PASS' if rns_complete else 'FAIL'}")
        print(f"retinue verified RNS's returned proof:  {'PASS' if retinue_verified else 'FAIL'}")
        print("=" * 68)
        ok = data_ok and rns_complete and retinue_verified
        print(f"R4 RESOURCE SEND INTEROP: {'PASS' if ok else 'FAIL'}")
        exit_code = 0 if ok else 1
        return exit_code
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        atexit.register(shutil.rmtree, cfg, ignore_errors=True); RNS.exit(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
