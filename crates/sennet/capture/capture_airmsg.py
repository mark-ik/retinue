"""Capture live over-the-air packets a Meshtastic-compatible node receives, black-box.

The observer node (OBS_PORT) is opened over USB; we send want_config (field 3, found
empirically) to start a client session, drain the config dump, then listen while a SECOND
node nearby transmits over the air. Received over-the-air packets are streamed to us as
FromRadio frames of a variant distinct from the config sections. We save them raw and record
their structure; meanings are not asserted here.

Usage: python capture_airmsg.py COM7 [seconds]
"""
import json, sys, time
from pathlib import Path
import serial

OBS = sys.argv[1] if len(sys.argv) > 1 else "COM7"
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 150


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


s = serial.Serial(OBS, 115200, timeout=0.2)
time.sleep(0.4)
s.reset_input_buffer()
s.write(frame(varint((3 << 3) | 0) + varint(0x11223344)))
s.flush()

# Phase 1: drain the config dump.
buf = bytearray()
last = time.time()
while time.time() - last < 1.5:
    c = s.read(8192)
    if c:
        buf.extend(c)
        last = time.time()
config_frames = deframe(buf)
print(f"config dump: {len(config_frames)} frames; now listening {SECS}s for over-the-air packets...")

# Phase 2: live listen for received over-the-air packets.
live = bytearray()
t0 = time.time()
last_report = 0
while time.time() - t0 < SECS:
    c = s.read(8192)
    if c:
        live.extend(c)
    n = len(deframe(live))
    if n != last_report:
        print(f"  [{int(time.time()-t0)}s] {n} live frames received over the air")
        last_report = n
s.close()

live_frames = deframe(live)
out = Path(__file__).parent.parent / "tests" / "fixtures" / "meshtastic_airmsg.json"
out.write_text(
    json.dumps(
        {
            "_comment": (
                "Live over-the-air packets received by a Meshtastic-compatible observer node "
                "and streamed over its client API, captured black-box 2026-07-22. A second node "
                "transmitted. frames = raw FromRadio payloads of received packets, hex. Field "
                "numbers/wire types are observable facts; meanings are NOT asserted."
            ),
            "observer_port": OBS,
            "config_frame_count": len(config_frames),
            "live_frame_count": len(live_frames),
            "frames": [f.hex() for f in live_frames],
        },
        indent=1,
    ),
    encoding="utf-8",
)
print(f"wrote {out} ({len(live_frames)} over-the-air frames)")
