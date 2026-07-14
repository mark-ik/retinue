"""Capture the resource protocol: RNS sends retinue a small multi-part resource.

retinue (resource_probe) dumps every decrypted link packet. We correlate with RNS's own
Resource internals via umsgpack to name the advertisement fields.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u capture_resource.py
"""
from __future__ import annotations
import re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
done = threading.Event()


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "resource_probe"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    def pump():
        for line in proc.stdout:
            line=line.rstrip(); lines.append(line); print(f"  [retinue] {line}")
    threading.Thread(target=pump, daemon=True).start()

    port=None; dl=time.time()+180
    while time.time()<dl and port is None:
        for line in list(lines):
            m=re.match(r"LISTENING (\d+)", line)
            if m: port=int(m.group(1)); break
        if proc.poll() is not None: return 1
        time.sleep(0.2)
    if port is None: proc.kill(); return 1

    cfg=Path(tempfile.mkdtemp(prefix="retinue-res-"))
    (cfg/"config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n"
        f"    enabled=yes\n    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    try:
        class Linker:
            aspect_filter="retinue.resource"
            def received_announce(self, destination_hash, announced_identity, app_data):
                if "l" in globals(): return
                globals()["l"]=1
                print(f"  RNS: linking to {destination_hash.hex()}")
                out=RNS.Destination(announced_identity, RNS.Destination.OUT,
                                    RNS.Destination.SINGLE, "retinue", "resource")
                link=RNS.Link(out)
                def est(lk):
                    print("  RNS: link up, sending a small multi-part resource")
                    # ~4 KB of structured bytes, small enough to read but multi-part.
                    data=bytes((i*7+3)&0xff for i in range(4096))
                    def prog(res): pass
                    def cb(res):
                        print(f"  RNS: resource transfer concluded status={res.status}")
                        done.set()
                    RNS.Resource(data, lk, callback=cb, progress_callback=prog)
                link.set_link_established_callback(est)
        RNS.Transport.register_announce_handler(Linker())
        print("waiting...\n")
        done.wait(timeout=25)
        time.sleep(1.5)

        # Summarise the packets retinue saw.
        print("\n"+"="*68)
        adv=None
        for line in lines:
            m=re.match(r"  \[retinue\] PKT ctx=0x([0-9a-f]+) len=(\d+) ([0-9a-f]+)", line)
            if not m: continue
            ctx=int(m.group(1),16); raw=bytes.fromhex(m.group(3))
            names={0x02:"RESOURCE_ADV",0x01:"RESOURCE",0x03:"RESOURCE_REQ",0x04:"RESOURCE_HMU",
                   0x05:"RESOURCE_PRF",0x06:"RESOURCE_ICL",0x07:"RESOURCE_RCL",0x00:"DATA",0xfe:"RTT"}
            print(f"ctx 0x{ctx:02x} {names.get(ctx,'?'):14s} {len(raw)} bytes")
            if ctx==0x02:
                adv=raw
        if adv:
            print(f"\nADVERTISEMENT raw: {adv.hex()}")
            try:
                from RNS.vendor import umsgpack
                u=umsgpack.unpackb(adv)
                print(f"  umsgpack: {u!r}")
                if isinstance(u,dict):
                    for k,v in u.items():
                        vr = v.hex() if isinstance(v,(bytes,bytearray)) else v
                        print(f"    {k!r}: {type(v).__name__} = {vr!r}"[:200])
            except Exception as e:
                print(f"  decode: {e}")
        print("="*68)
        return 0
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        RNS.exit(); shutil.rmtree(cfg, ignore_errors=True)


if __name__=="__main__":
    raise SystemExit(main())
