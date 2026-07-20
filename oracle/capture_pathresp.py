"""Capture RNS's RESPONSE to a path request: the path-response context byte.

Recorder socket. RNS (transport enabled) dials in and owns a SINGLE destination.
We announce nothing on RNS's behalf beyond its own announce; then we send a
well-formed path request FOR RNS's own destination and observe what RNS emits
back. Expectation (O-15): an announce (packet_type=1) with context 0x0B.

Run from oracle/:  ./.venv/Scripts/python.exe -u capture_pathresp.py
"""
import socket, threading, time, tempfile, os
from pathlib import Path
import RNS

PORT = 42693
FLAG, ESC, MASK = 0x7E, 0x7D, 0x20
PR_DEST = bytes.fromhex("6b9f66014d9853faab220fba47d02761")
rec = bytearray()
stop = threading.Event()


def frame(b):
    out = bytearray([FLAG])
    for x in b:
        if x == FLAG:
            out += bytes([ESC, FLAG ^ MASK])
        elif x == ESC:
            out += bytes([ESC, ESC ^ MASK])
        else:
            out.append(x)
    out.append(FLAG)
    return bytes(out)


def deframe(s):
    fr, cur, inf, esc = [], bytearray(), False, False
    for b in s:
        if b == FLAG:
            if inf and cur:
                fr.append(bytes(cur))
            cur, inf, esc = bytearray(), True, False
        elif not inf:
            continue
        elif esc:
            cur.append(b ^ MASK)
            esc = False
        elif b == ESC:
            esc = True
        else:
            cur.append(b)
    return fr


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(1)
srv.settimeout(1.0)

cfg = Path(tempfile.mkdtemp())
(cfg / "config").write_text(
    "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n  panic_on_interface_error = No\n"
    "\n[logging]\n  loglevel=3\n\n[interfaces]\n  [[c]]\n    type=TCPClientInterface\n    enabled=yes\n"
    f"    target_host=127.0.0.1\n    target_port={PORT}\n",
    encoding="utf-8",
)
RNS.Reticulum(configdir=str(cfg))
ident = RNS.Identity()
dest = RNS.Destination(ident, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "probe")
print("RNS owns dest:", dest.hash.hex())

conn = None
for _ in range(20):
    try:
        conn, _ = srv.accept()
        break
    except TimeoutError:
        continue
conn.settimeout(0.5)


def rd():
    while not stop.is_set():
        try:
            c = conn.recv(65536)
            if not c:
                break
            rec.extend(c)
        except TimeoutError:
            continue
        except OSError:
            break


threading.Thread(target=rd, daemon=True).start()
time.sleep(1.0)
dest.announce()  # let RNS emit its own announce first
time.sleep(1.5)
mark = len(rec)

# Send a path request FOR RNS's own destination.
tag = os.urandom(16)
pr = bytes([0x08, 0x00]) + PR_DEST + bytes([0x00]) + dest.hash + tag
conn.sendall(frame(pr))
print("sent path request for RNS's own dest")
time.sleep(2.5)

tail = bytes(rec[mark:])
print("bytes after request:", len(tail))
for f in deframe(tail):
    if len(f) >= 19:
        ptype = f[0] & 0b11
        print(
            f"frame {len(f)}B: flags=0x{f[0]:02x} pkt_type={ptype} "
            f"dest_type={(f[0] >> 2) & 0b11} ctx=0x{f[18]:02x} dest={f[2:18].hex()}"
        )
        if ptype == 1:  # announce
            print(f"  -> ANNOUNCE, context byte = 0x{f[18]:02x}"
                  f"  (matches RNS dest: {f[2:18].hex() == dest.hash.hex()})")

stop.set()
RNS.exit()
