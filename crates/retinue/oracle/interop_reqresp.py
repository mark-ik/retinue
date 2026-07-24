"""R3 request/response gate: retinue and RNS 1.4.0 exchange requests both ways.

  1. retinue -> RNS. retinue requests /echo; RNS's handler answers; retinue matches the
     response to its request by id.
  2. RNS -> retinue. RNS requests /svc on retinue's announced destination; retinue answers;
     RNS's response_callback fires with retinue's data.

Local gate. Same black-box discipline.

Run from the oracle/ directory:  ./.venv/Scripts/python.exe -u interop_reqresp.py
"""

from __future__ import annotations

import atexit
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import RNS

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEST_SEED = bytes([0x11] * 64)  # the destination retinue calls into

rns_response = {}
response_seen = threading.Event()


def echo_handler(path, data, request_id, link_id, remote_identity, requested_at):
    print(f"  RNS /echo handler: data={bytes(data)!r}")
    return b"rns-echo:" + bytes(data)


def main() -> int:
    print(f"RNS {RNS.__version__}\n")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet", "--example", "reqresp_interop"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    lines = []

    def pump():
        for line in proc.stdout:
            line = line.rstrip(); lines.append(line); print(f"  [retinue] {line}")
    threading.Thread(target=pump, daemon=True).start()

    port = None
    dl = time.time() + 180
    while time.time() < dl and port is None:
        for line in list(lines):
            m = re.match(r"LISTENING (\d+)", line)
            if m:
                port = int(m.group(1)); break
        if proc.poll() is not None:
            return 1
        time.sleep(0.2)
    if port is None:
        proc.kill(); return 1

    cfg = Path(tempfile.mkdtemp(prefix="retinue-rri-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n\n[logging]\n  loglevel = 3\n\n[interfaces]\n"
        "  [[retinue]]\n    type = TCPClientInterface\n    enabled = yes\n"
        f"    target_host = 127.0.0.1\n    target_port = {port}\n",
        encoding="utf-8",
    )
    RNS.Reticulum(configdir=str(cfg))
    exit_code = 1
    try:
        # Our /echo responder that retinue calls into.
        identity = RNS.Identity.from_bytes(DEST_SEED)
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                               "retinue", "reqresp")
        dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
        dest.accepts_links(True)
        dest.register_request_handler("/echo", response_generator=echo_handler,
                                      allow=RNS.Destination.ALLOW_ALL)
        print(f"RNS /echo responder {dest.hash.hex()}")

        # When retinue announces its /svc destination, link to it and request /svc.
        class CallRetinue:
            aspect_filter = "retinue.svc"

            def received_announce(self, destination_hash, announced_identity, app_data):
                if "done" in rns_response:
                    return
                rns_response["done"] = True
                print(f"  RNS: saw retinue /svc {destination_hash.hex()}, linking to request it")
                out = RNS.Destination(announced_identity, RNS.Destination.OUT,
                                      RNS.Destination.SINGLE, "retinue", "svc")
                link = RNS.Link(out)

                def established(l):
                    def on_response(receipt):
                        print(f"  RNS: got retinue's response: {bytes(receipt.response)!r}")
                        rns_response["data"] = bytes(receipt.response)
                        response_seen.set()

                    def on_failed(receipt):
                        print("  RNS: request to retinue FAILED")
                        response_seen.set()

                    l.request("/svc", data=b"hi-retinue",
                              response_callback=on_response, failed_callback=on_failed, timeout=8)

                link.set_link_established_callback(established)

        RNS.Transport.register_announce_handler(CallRetinue())
        print("waiting...\n")

        dl = time.time() + 35
        while time.time() < dl and "DONE" not in "\n".join(lines):
            time.sleep(0.2)
        response_seen.wait(timeout=3)
        time.sleep(0.5)

        joined = "\n".join(lines)
        print("\n" + "=" * 68)
        r2r = re.search(r"RECV_RESPONSE data=(\S+) id_match=(\w+)", joined)
        retinue_got = bool(r2r and r2r.group(2) == "true")
        rns_got = rns_response.get("data") == b"retinue-echo:hi-retinue"
        answered = "ANSWERED_REQUEST" in joined

        print(f"retinue -> RNS request (matched):  "
              f"{'PASS' if retinue_got else 'FAIL'}"
              + (f"  data={r2r.group(1)}" if r2r else ""))
        print(f"RNS -> retinue request answered:   {'PASS' if (answered and rns_got) else 'FAIL'}"
              f"  (RNS got {rns_response.get('data')!r})")
        print("=" * 68)
        ok = retinue_got and answered and rns_got
        print(f"R3 REQUEST/RESPONSE INTEROP: {'PASS' if ok else 'FAIL'}")
        exit_code = 0 if ok else 1
        return exit_code
    finally:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        atexit.register(shutil.rmtree, cfg, ignore_errors=True)
        RNS.exit(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
