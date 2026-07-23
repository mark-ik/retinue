"""Endpoint stream gate: retinue's Endpoint exposes a link as an AsyncRead/AsyncWrite
stream, and RNS exchanges bytes over it via a link Channel/Buffer.

This is the shape mere's Transport trait needs. RNS links to retinue's announced /stream
destination, sends bytes over a RawChannel buffer, and reads retinue's echo. Both sides
seeing the right bytes proves retinue's endpoint runtime backs a bilateral byte stream.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_endpoint_stream.py
"""
from __future__ import annotations
import atexit, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
got = {"rx": []}
done = threading.Event()
MESSAGE = b"hello-over-stream"


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(["cargo", "run", "--quiet", "--example", "endpoint_stream"],
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

    cfg = Path(tempfile.mkdtemp(prefix="retinue-eps-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport=No\n  share_instance=No\n  panic_on_interface_error=No\n"
        f"\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[retinue]]\n    type=TCPClientInterface\n    enabled=yes\n"
        f"    target_host=127.0.0.1\n    target_port={port}\n", encoding="utf-8")
    RNS.Reticulum(configdir=str(cfg))
    exit_code = 1
    try:
        class Linker:
            aspect_filter = "retinue.stream"
            def received_announce(self, destination_hash, announced_identity, app_data):
                if getattr(Linker, "x", False): return
                Linker.x = True
                out = RNS.Destination(announced_identity, RNS.Destination.OUT,
                                      RNS.Destination.SINGLE, "retinue", "stream")
                link = RNS.Link(out)
                def est(lk):
                    print("  RNS: link up, sending a raw link data packet")
                    def on_packet(message, packet):
                        got["rx"].append(bytes(message))
                        print(f"  RNS: received {bytes(message)!r}")
                        done.set()
                    lk.set_packet_callback(on_packet)
                    # Raw bilateral link data, the lane mere uses (not RNS Channel/Buffer).
                    RNS.Packet(lk, MESSAGE).send()
                    print(f"  RNS: sent {MESSAGE!r}")
                link.set_link_established_callback(est)
        RNS.Transport.register_announce_handler(Linker())
        print("waiting...\n")
        done.wait(timeout=30)
        time.sleep(1.5)

        joined = "\n".join(lines)
        retinue_got = "RECV hello-over-stream" in joined
        rns_got_echo = any(b"echo:hello-over-stream" == m for m in got["rx"])
        print("\n" + "=" * 68)
        print(f"retinue read from the stream:    {'PASS' if retinue_got else 'FAIL'}")
        print(f"RNS read retinue's echo back:    {'PASS' if rns_got_echo else 'FAIL'} "
              f"(got {got['rx']!r})")
        print("=" * 68)
        ok = retinue_got and rns_got_echo
        print(f"ENDPOINT STREAM INTEROP: {'PASS' if ok else 'FAIL'}")
        exit_code = 0 if ok else 1
        return exit_code
    finally:
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired: proc.kill()
        atexit.register(shutil.rmtree, cfg, ignore_errors=True); RNS.exit(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
