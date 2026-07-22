"""Capture a Meshtastic-compatible device's config stream, black-box.

Sends want_config (field 3 of the request message, discovered empirically by probing which
field number triggers a response — no schema was read) framed in the publicly documented
Stream API (0x94 0xc3, big-endian u16 length). Collects the FromRadio frames the device
streams back and saves them raw. The field NUMBERS and wire TYPES are recorded; their
application meanings are not asserted here.

Usage: python capture_config.py COM7
"""
import json, sys, time
from pathlib import Path
import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM7"
WANT_CONFIG_FIELD = 3  # discovered by empirical probe, not read from any schema


def frame(pb):
    return bytes([0x94, 0xC3]) + len(pb).to_bytes(2, "big") + pb


def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def deframe(buf):
    frames, i = [], 0
    while i < len(buf) - 3:
        if buf[i] == 0x94 and buf[i + 1] == 0xC3:
            ln = (buf[i + 2] << 8) | buf[i + 3]
            if i + 4 + ln <= len(buf):
                frames.append(bytes(buf[i + 4 : i + 4 + ln]))
                i += 4 + ln
                continue
        i += 1
    return frames


s = serial.Serial(PORT, 115200, timeout=0.2)
time.sleep(0.4)
s.reset_input_buffer()
s.write(frame(varint((WANT_CONFIG_FIELD << 3) | 0) + varint(0x11223344)))
s.flush()

buf = bytearray()
last = time.time()
while time.time() - last < 1.5:  # stop after 1.5s of quiet
    c = s.read(8192)
    if c:
        buf.extend(c)
        last = time.time()
s.close()

frames = deframe(buf)
print(f"captured {len(buf)} bytes, {len(frames)} FromRadio frames")

out = Path(__file__).parent.parent / "tests" / "fixtures" / "meshtastic_config.json"
out.write_text(
    json.dumps(
        {
            "_comment": (
                "Meshtastic-compatible device config stream, captured black-box 2026-07-22. "
                "want_config request = field 3 (discovered by empirically probing which field "
                "number triggers a response; no schema was read). Stream API framing (0x94 0xc3 "
                "+ BE u16 len). frames = the raw FromRadio payloads streamed back, hex. Field "
                "NUMBERS/wire TYPES are observable facts; meanings are NOT asserted here."
            ),
            "port": PORT,
            "want_config_field": WANT_CONFIG_FIELD,
            "frame_count": len(frames),
            "frames": [f.hex() for f in frames],
        },
        indent=1,
    ),
    encoding="utf-8",
)
print(f"wrote {out}")
