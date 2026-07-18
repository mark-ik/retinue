"""Capture the RNS 1.3.8 Channel wire into a deterministic fixture.

Same black-box discipline: we run RNS and observe it; we never read its source. Here
the observation is direct — RNS's own `Channel.Envelope.pack()` is a pure function of
(msgtype, sequence, payload), so we call it on known inputs and read the bytes it
emits. We also record the Channel's public protocol constants (sequence modulus,
window sizing, RTT tiers) and the link packet context Channel rides on.

Findings (all from public API, no source read):
  * A Channel message is a link data packet with context CHANNEL = 14 (0x0e).
  * The envelope is  [msgtype u16 BE][sequence u16 BE][length u16 BE][payload].
  * Sequence is windowed 16-bit (SEQ_MODULUS = 65536).
  * The send window is dynamic: it grows toward an RTT-tiered maximum.

Writes ../tests/fixtures/channel_wire.json for a Rust test to assert retinue's
Channel envelope encoding matches, with no Python at test time.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_channel.py
"""

from __future__ import annotations

import json
from pathlib import Path

import RNS
from RNS.Channel import Channel, Envelope, MessageBase

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"


class ProbeMessage(MessageBase):
    """A minimal Channel message: an opaque payload under a fixed msgtype."""

    MSGTYPE = 0xABCD

    def __init__(self, payload: bytes = b""):
        self.payload = payload

    def pack(self) -> bytes:
        return self.payload

    def unpack(self, raw: bytes) -> None:
        self.payload = raw


def main() -> int:
    print(f"RNS {RNS.__version__}")

    # Envelope byte layout: pack() is pure over (msgtype, sequence, payload), so we
    # read its output directly. Each vector cross-checks by decoding back.
    vectors = []
    for seq, payload in [(7, b"hello"), (0, b""), (65535, b"AB"), (258, bytes(range(20)))]:
        packed = Envelope(outlet=None, message=ProbeMessage(payload), sequence=seq).pack()
        # Cross-check the field split we claim: msgtype(2) seq(2) len(2) payload.
        assert packed[0:2] == ProbeMessage.MSGTYPE.to_bytes(2, "big")
        assert packed[2:4] == seq.to_bytes(2, "big")
        assert int.from_bytes(packed[4:6], "big") == len(payload)
        assert packed[6:] == payload
        vectors.append(
            {"sequence": seq, "msgtype": ProbeMessage.MSGTYPE, "payload_hex": payload.hex(), "packed_hex": packed.hex()}
        )
        print(f"  seq={seq:<5} len={len(payload):<3} -> {packed.hex()}")

    constants = {name: getattr(Channel, name) for name in [
        "SEQ_MAX", "SEQ_MODULUS",
        "WINDOW", "WINDOW_MIN", "WINDOW_MAX", "WINDOW_FLEXIBILITY",
        "WINDOW_MAX_SLOW", "WINDOW_MAX_MEDIUM", "WINDOW_MAX_FAST",
        "WINDOW_MIN_LIMIT_SLOW", "WINDOW_MIN_LIMIT_MEDIUM", "WINDOW_MIN_LIMIT_FAST",
        "RTT_SLOW", "RTT_MEDIUM", "RTT_FAST", "FAST_RATE_THRESHOLD",
    ]}

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "channel_wire.json").write_text(
        json.dumps(
            {
                "description": (
                    "RNS 1.3.8 Channel wire, observed black-box. The envelope is "
                    "[msgtype u16 BE][sequence u16 BE][length u16 BE][payload], carried in a "
                    "link data packet with context CHANNEL (14). Sequence is windowed 16-bit. "
                    "packed_hex is RNS's own Envelope.pack() output; a Rust test reproduces it."
                ),
                "rns_version": RNS.__version__,
                "packet_context_channel": RNS.Packet.CHANNEL,
                "envelope_layout": "msgtype:u16be | sequence:u16be | length:u16be | payload",
                "constants": constants,
                "envelope_vectors": vectors,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"packet context CHANNEL = {RNS.Packet.CHANNEL}")
    print(f"seq modulus = {constants['SEQ_MODULUS']}, window {constants['WINDOW']}..{constants['WINDOW_MAX']}")
    print(f"wrote channel_wire.json ({len(vectors)} envelope vectors + {len(constants)} constants)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
