"""Capture the RNode RX direction: how a received LoRa frame reaches the host.

Two real RNodes, one machine. The receiver (RX_PORT) runs RNS under a pyserial tee
logging every serial byte; the transmitter (TX_PORT) runs a plain second RNS process
that announces a destination a few times. The tee log then contains the radio->host
delivery of genuinely-received frames: the KISS data framing and wherever RSSI/SNR
ride. RNS is a black box throughout.

Run from oracle/ with both RNodes attached:
    ./.venv/Scripts/python.exe -u capture_rnode_rx.py COM5 COM6
(receiver port first, transmitter port second)
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import serial as pyserial

RX_PORT = sys.argv[1] if len(sys.argv) > 1 else "COM5"
TX_PORT = sys.argv[2] if len(sys.argv) > 2 else "COM6"

RADIO = (
    "    frequency = 915000000\n"
    "    bandwidth = 125000\n"
    "    txpower = 7\n"
    "    spreadingfactor = 8\n"
    "    codingrate = 5\n"
)


def rns_config(port: str) -> str:
    cfg = Path(tempfile.mkdtemp(prefix=f"retinue-rnode-{port}-"))
    (cfg / "config").write_text(
        "[reticulum]\n  enable_transport = No\n  share_instance = No\n"
        "  panic_on_interface_error = No\n"
        "\n[logging]\n  loglevel = 2\n"
        "\n[interfaces]\n  [[rnode]]\n    type = RNodeInterface\n    enabled = yes\n"
        f"    port = {port}\n" + RADIO,
        encoding="utf-8",
    )
    return str(cfg)


if "--transmit" in sys.argv:
    import RNS

    RNS.Reticulum(configdir=rns_config(TX_PORT))
    time.sleep(12.0)  # let the interface come fully online
    ident = RNS.Identity()
    dest = RNS.Destination(
        ident, RNS.Destination.IN, RNS.Destination.SINGLE, "retinue", "rxcap"
    )
    for i in range(3):
        dest.announce()
        print(f"TX announce {i + 1}")
        time.sleep(3.0)
    RNS.exit()
    sys.exit(0)

# --- receiver role, with the tee ---
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

import RNS  # noqa: E402

got: list[str] = []


class AnyAnnounce:
    aspect_filter = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        got.append(destination_hash.hex())
        print(f"RX: RNS validated announce from {destination_hash.hex()}")


print(f"receiver starting on {RX_PORT}")
RNS.Reticulum(configdir=rns_config(RX_PORT))
RNS.Transport.register_announce_handler(AnyAnnounce())
time.sleep(12.0)
rx_ready_marker = len(LOG)
print(f"receiver online ({rx_ready_marker} events); starting transmitter on {TX_PORT}")

tx = subprocess.Popen(
    [sys.executable, "-u", __file__, RX_PORT, TX_PORT, "--transmit"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)
out, _ = tx.communicate(timeout=180)
for line in out.splitlines():
    if "TX announce" in line or "error" in line.lower():
        print(f"  [tx] {line.strip()}")
time.sleep(4.0)

fixture = Path(__file__).parent.parent / "tests" / "fixtures" / "rnode_rx_capture.json"
fixture.write_text(
    json.dumps(
        {
            "_comment": (
                "RNode radio->host RX capture, 2026-07-21: two real RNodes (receiver "
                "Heltec V4 c3:c8:3f, transmitter Heltec T114 c2:c7:3c), RNS 1.3.8 both "
                "ends, 915 MHz BW125 SF8 CR5, 7 dBm. Events after rx_ready_marker "
                "include the receiver's radio->host delivery of genuinely received "
                "announces; rns_validated lists the announces RNS accepted end-to-end."
            ),
            "rx_port": RX_PORT,
            "tx_port": TX_PORT,
            "config": {
                "frequency": 915000000,
                "bandwidth": 125000,
                "txpower": 7,
                "spreadingfactor": 8,
                "codingrate": 5,
            },
            "rx_ready_marker": rx_ready_marker,
            "rns_validated": got,
            "events": LOG,
        },
        indent=1,
    ),
    encoding="utf-8",
)
print(f"wrote {fixture} ({len(LOG)} events, {len(got)} announces validated by RNS)")
RNS.exit()
