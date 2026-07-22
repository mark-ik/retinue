# Observed structure of a config stream

Facts observed from a black-box capture (`tests/fixtures/meshtastic_config.json`,
`capture/capture_config.py`), decoded with Sennet's own protobuf reader. Field
numbers and wire types are observable facts. **Meanings are not asserted here**;
the semantic reconstruction is a separate process gated on counsel review (see
`PROVENANCE.md`).

## Handshake

- Request framing: the Stream API (`0x94 0xc3` + big-endian u16 length).
- The request that triggers the config stream is field **3** (varint) of the
  request message, carrying a client nonce. Discovered by probing which field
  number produces a response, not by reading a schema: field 3 returned 47
  frames; fields 1/4/5/6/7 returned a short (~212-byte) reply; fields 2/8
  returned nothing.
- DTR state does not matter, and no wake sequence is needed.

## Response stream

47 FromRadio frames, each a single top-level protobuf field (a oneof variant):

| top-level field | frames | wire shape |
|---|---|---|
| 2 | 1 | nested message |
| 3 | 1 | nested message |
| 4 | 1 | nested message |
| 5 | 10 | nested message |
| 7 | 1 | nested message |
| 9 | 16 | nested message |
| 10 | 8 | nested message |
| 13 | 1 | nested message |
| 15 | 7 | nested message |
| 17 | 1 | **scalar (varint)** |

- 46 of 47 frames carry a nested message; exactly one carries a scalar varint.
  That single scalar is the stream's completion marker (field 17 here) — a
  structural landmark, distinct from every config-bearing frame.
- The repeated variants (field 9 x16, field 5 x10, field 10 x8, field 15 x7)
  are the list-shaped parts of the config (repeated entries streamed one frame
  each); the singletons (2, 3, 4, 7, 13) are one-per-device config sections.

## Over-the-air received-packet envelope

A second node transmitted; the observer received packets over the air and streamed them out
its client API (`capture/capture_airmsg.py` -> `tests/fixtures/meshtastic_airmsg.json`).
Every received packet is one top-level variant (field **2**, distinct from the config
variants) wrapping a nested envelope. The observed tree, as bytes (field numbers, wire types,
and which values held constant across captures), with no meanings attached:

```text
field 2 (nested)                        the received-packet variant
  field 1  i32   constant per sender    (a 4-byte id)
  field 2  i32   constant 0xffffffff    (a 4-byte id; all-ones here)
  field 4 (nested)                      a sub-message
    field 1  varint                     (a small tag; differed by message type)
    field 2 / field 6 (nested)          the innermost payload, whose shape varied by tag
  field 6  i32   incremented per frame  (monotonic; a counter or time)
  field 7  i32                          (a 4-byte id)
  field 9  varint constant 3
  field 11 varint constant 16
```

Two of three frames shared an identical inner shape (same tag at `field 4 > field 1`); the
third had a larger, differently-shaped inner payload. This is the envelope every application
message rides, whatever its type; it is recorded here only as the shape of the bytes.

## Over-the-air text message

A message sent from a phone app was received over the air by the observer node and streamed
out its client API (`tests/fixtures/meshtastic_textmsg.json`). Descending the envelope to the
decoded sub-message (`field 2 > field 4`), its two fields were:

- `field 1` varint = **1** — the tag (distinct from the telemetry tag 67 seen on other
  packets).
- `field 2` bytes = the payload, which was **valid readable UTF-8**: the exact message that
  was sent.

That a readable message rode under tag 1 at this path is a direct observation (we read the
text). It is recorded as the observed fact it is; the fuller schema — every tag, every message
type, field names — remains for the gated reconstruction below.

## What comes next (and the discipline for it)

Reconstructing what each variant and its inner fields *mean* is done only from
this observation plus public prose, authored independently, recorded per
message, and reviewed by counsel before permissive publication. Nothing in this
file crosses that line: it is the shape of the bytes, not anyone's schema.
