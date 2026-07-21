"""Capture the RNode host<->device serial protocol from RNS 1.3.8, black-box.

A pyserial tee: serial.Serial is wrapped so every byte RNS's RNodeInterface writes to or
reads from the real device is logged, timestamped and direction-tagged. RNS itself is run
as a black box (its source is never read); the log records the boundary conversation:
the KISS-framed init/SetHardware sequence (frequency, bandwidth, spreading factor, coding
rate, TX power), the device's state readbacks, and one transmitted data frame.

Run from oracle/ with the RNode on the given port:
    ./.venv/Scripts/python.exe -u capture_rnode_serial.py COM5
"""

import json
import sys
import time
from pathlib import Path

import serial as pyserial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM5"
LOG: list[dict] = []
T0 = time.time()

RealSerial = pyserial.Serial


class TeeSerial(RealSerial):
    def write(self, data):
        LOG.append(
            {"t": round(time.time() - T0, 4), "dir": "host->rnode", "hex": bytes(data).hex()}
        )
        return super().write(data)

    def read(self, size=1):
        data = super().read(size)
        if data:
            LOG.append(
                {"t": round(time.time() - T0, 4), "dir": "rnode->host", "hex": bytes(data).hex()}
            )
        return data


pyserial.Serial = TeeSerial

import tempfile

import RNS  # noqa: E402  (imported after the tee is installed)

cfg = Path(tempfile.mkdtemp(prefix="retinue-rnode-"))
(cfg / "config").write_text(
    "[reticulum]\n  enable_transport = No\n  share_instance = No\n  panic_on_interface_error = No\n"
    "\n[logging]\n  loglevel = 4\n"
    "\n[interfaces]\n  [[rnode]]\n    type = RNodeInterface\n    enabled = yes\n"
    f"    port = {PORT}\n"
    "    frequency = 915000000\n"
    "    bandwidth = 125000\n"
    "    txpower = 7\n"
    "    spreadingfactor = 8\n"
    "    codingrate = 5\n",
    encoding="utf-8",
)

print(f"starting RNS with RNodeInterface on {PORT} (915 MHz, BW125, SF8, CR5, 7 dBm)")
RNS.Reticulum(configdir=str(cfg))
time.sleep(10.0)  # let the interface fully come online (it revalidates config ~8s in)
init_marker = len(LOG)
print(f"init complete: {init_marker} logged serial events")

# One small transmission, so the data-frame KISS format is in the capture too.
ident = RNS.Identity()
dest = RNS.Destination(
    ident, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "rnodecap"
)
dest.announce()
print("announce queued; letting it transmit...")
time.sleep(8.0)

out = Path(__file__).parent.parent / "tests" / "fixtures" / "rnode_serial_capture.json"
out.write_text(
    json.dumps(
        {
            "_comment": (
                "RNS 1.3.8 RNodeInterface <-> RNode firmware 1.86 (Heltec T114, c2:c7:3c) "
                "serial capture via a pyserial tee, 2026-07-21. Config: 915 MHz, BW 125k, "
                "SF8, CR5, 7 dBm. Events are timestamped bytes with direction; the early "
                "host->rnode events are the KISS init/SetHardware sequence, the announce "
                "near the end is a data frame. init_events marks the end of interface init."
            ),
            "port": PORT,
            "config": {
                "frequency": 915000000,
                "bandwidth": 125000,
                "txpower": 7,
                "spreadingfactor": 8,
                "codingrate": 5,
            },
            "init_events": init_marker,
            "events": LOG,
        },
        indent=1,
    ),
    encoding="utf-8",
)
print(f"wrote {out} ({len(LOG)} events)")
RNS.exit()
