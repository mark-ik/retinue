"""Capture the RNS 1.3.8 Buffer stream-frame wire into a deterministic fixture.

Same black-box discipline as capture_channel.py: we run RNS and observe it, never
reading its source. RNS's `Buffer` rides a `Channel` — each stream chunk is a
`StreamDataMessage`, a Channel `MessageBase` whose `pack()` is a pure function of
(stream_id, data, eof, compressed). We call it on known inputs and read the bytes.

Findings (all from public API + observed pack() output, no source read):
  * A Buffer stream chunk is a Channel message with msgtype STREAM = 0xff00.
  * The frame is  [u16 BE header][data], header = eof<<15 | compressed<<14 | stream_id.
  * stream_id is 14-bit (STREAM_ID_MAX = 0x3fff); the top two bits are the flags.
  * pack() stores data verbatim even when compressed=1 — compression is a transform
    applied to `data` before framing, not part of the frame layout.
  * MAX_DATA_LEN = 423 data bytes/chunk; OVERHEAD = 8 (2 stream header + 6 envelope).

Writes ../tests/fixtures/buffer_wire.json for a Rust gold test to assert retinue's
StreamFrame encoding matches, with no Python at test time.

Run from the oracle/ directory:

    ./.venv/Scripts/python.exe -u capture_buffer.py
"""

from __future__ import annotations

import json
from pathlib import Path

import RNS
from RNS.Buffer import StreamDataMessage

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"


def main() -> int:
    print(f"RNS {RNS.__version__}")

    # pack() is pure over (stream_id, data, eof, compressed); read its output directly.
    # Each vector cross-checks the field split we claim: header u16 BE, then raw data.
    vectors = []
    matrix = [
        (0, b"", False, False),
        (0, b"hi", False, False),
        (1, b"hi", False, False),
        (255, b"hi", False, False),
        (256, b"hi", False, False),
        (StreamDataMessage.STREAM_ID_MAX, b"hi", False, False),  # all 14 id bits set
        (7, b"", True, False),                                   # eof, no data
        (7, b"AB", True, False),                                 # eof + data
        (7, b"AB", False, True),                                 # compressed flag
        (7, b"AB", True, True),                                  # eof + compressed
    ]
    for sid, data, eof, comp in matrix:
        packed = StreamDataMessage(stream_id=sid, data=data, eof=eof, compressed=comp).pack()
        header = (0x8000 if eof else 0) | (0x4000 if comp else 0) | sid
        # Cross-check the layout we claim, from the bytes alone.
        assert packed[0:2] == header.to_bytes(2, "big"), packed.hex()
        assert packed[2:] == data, packed.hex()  # data verbatim, even when compressed=1
        vectors.append({
            "stream_id": sid,
            "eof": eof,
            "compressed": comp,
            "data_hex": data.hex(),
            "packed_hex": packed.hex(),
        })
        print(f"  sid={sid:<6} eof={int(eof)} comp={int(comp)} len={len(data):<3} -> {packed.hex()}")

    constants = {name: getattr(StreamDataMessage, name) for name in [
        "MSGTYPE", "STREAM_ID_MAX", "MAX_DATA_LEN", "OVERHEAD",
    ]}

    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / "buffer_wire.json").write_text(
        json.dumps(
            {
                "description": (
                    "RNS 1.3.8 Buffer stream-frame wire, observed black-box. A stream chunk "
                    "is a Channel message with msgtype STREAM (0xff00); the frame is "
                    "[u16 BE header][data], header = eof<<15 | compressed<<14 | stream_id "
                    "(14-bit). packed_hex is RNS's own StreamDataMessage.pack() output; a Rust "
                    "gold test reproduces it. Data is stored verbatim: the compressed flag "
                    "marks a bz2 transform applied to `data` upstream, not a framing change."
                ),
                "rns_version": RNS.__version__,
                "frame_layout": "header:u16be (eof:1 | compressed:1 | stream_id:14) | data",
                "constants": constants,
                "frame_vectors": vectors,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"stream msgtype = {hex(constants['MSGTYPE'])}, stream_id_max = {constants['STREAM_ID_MAX']}")
    print(f"max_data_len = {constants['MAX_DATA_LEN']}, overhead = {constants['OVERHEAD']}")
    print(f"wrote buffer_wire.json ({len(vectors)} frame vectors + {len(constants)} constants)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
