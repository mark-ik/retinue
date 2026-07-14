"""Capture the path-request packet format from RNS 1.3.8.

A recorder socket that speaks nothing; RNS dials in, and we ask it to request a path to a
made-up destination. Whatever it emits to that well-known destination is the format.
"""
import socket, threading, time, tempfile, hashlib
from pathlib import Path
import RNS

PORT = 42692
FLAG, ESC, MASK = 0x7E, 0x7D, 0x20
rec = bytearray(); stop = threading.Event()


def deframe(s):
    fr, cur, inf, esc = [], bytearray(), False, False
    for b in s:
        if b == FLAG:
            if inf and cur: fr.append(bytes(cur))
            cur, inf, esc = bytearray(), True, False
        elif not inf: continue
        elif esc: cur.append(b ^ MASK); esc = False
        elif b == ESC: esc = True
        else: cur.append(b)
    return fr


srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT)); srv.listen(1); srv.settimeout(1.0)

cfg = Path(tempfile.mkdtemp())
(cfg/"config").write_text(
    "[reticulum]\n  enable_transport = No\n  share_instance = No\n  panic_on_interface_error = No\n"
    "\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[c]]\n    type=TCPClientInterface\n    enabled=yes\n"
    f"    target_host=127.0.0.1\n    target_port={PORT}\n", encoding="utf-8")
RNS.Reticulum(configdir=str(cfg))

conn = None
for _ in range(20):
    try: conn, _ = srv.accept(); break
    except TimeoutError: continue
conn.settimeout(0.5)

def rd():
    while not stop.is_set():
        try:
            c = conn.recv(65536)
            if not c: break
            rec.extend(c)
        except TimeoutError: continue
        except OSError: break
threading.Thread(target=rd, daemon=True).start()

time.sleep(1.5)
mark = len(rec)

# The well-known path-request destination, for reference.
pr_name = RNS.Destination.app_and_aspects_from_name  # noqa
target = bytes.fromhex("00112233445566778899aabbccddeeff")
print("requesting path to", target.hex())
RNS.Transport.request_path(target)
time.sleep(2.0)

tail = bytes(rec[mark:])
print("bytes after request:", len(tail))
for f in deframe(tail):
    print(f"frame {len(f)}B: {f.hex()}")
    if len(f) >= 19:
        print(f"  flags=0x{f[0]:02x} type={f[0]&0b11} dest_type={(f[0]>>2)&0b11} "
              f"ctx=0x{f[18]:02x} dest={f[2:18].hex()} payload={f[19:].hex()}")

# The path-request destination hash, computed for comparison.
h = hashlib.sha256(b"rnstransport.path.request").digest()[:10]
print("name_hash(rnstransport.path.request):", h.hex())
try:
    d = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, "rnstransport", "path", "request")
    print("path.request dest hash:", d.hash.hex())
except Exception as e:
    print("dest calc:", e)

stop.set(); RNS.exit()
