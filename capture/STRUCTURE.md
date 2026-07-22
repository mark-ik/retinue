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

## What comes next (and the discipline for it)

Reconstructing what each variant and its inner fields *mean* is done only from
this observation plus public prose, authored independently, recorded per
message, and reviewed by counsel before permissive publication. Nothing in this
file crosses that line: it is the shape of the bytes, not anyone's schema.
