# Sennet provenance

Sennet is a clean-room implementation of interoperability with an existing LoRa
mesh messaging protocol. Its legal value depends on that cleanliness, so this
file records the discipline, kept current as the crate grows.

## The rule

Everything in this crate is derived from exactly three kinds of source:

1. **Publicly documented byte and frame formats** — layouts published as prose
   or diagrams on public documentation sites. A byte layout is a fact, not a
   copyrightable expression.
2. **Google's public protobuf wire standard** (protobuf.dev, "Encoding"): the
   varint/tag/wire-type encoding, which is an open specification independent of
   any schema. `src/protobuf.rs` is a generic reader for it and knows nothing
   about any message's meaning.
3. **Direct observation of bytes a device emits**, captured black-box (a serial
   or radio tee), the same discipline retinue uses against RNS. What a device
   puts on a wire is a fact we may observe and reproduce.

## What is never done

- No third-party protocol implementation source is read (firmware, client
  libraries, tooling).
- No third-party schema definition (`.proto` files) is read, and `protoc` is
  never run against one.
- Application message *semantics* (which field number means which application
  concept) are reconstructed only from observation and public prose, authored
  here independently, never copied. This is the one layer where the
  facts-versus-expression line is genuinely close; it is documented per message
  as it is built, and permissive publication of that layer waits for a counsel
  review of the reconstruction record.

## Naming and non-endorsement

The crate is named independently (Sennet) and carries non-endorsement language:
it is not affiliated with or endorsed by any existing mesh project, and it must
never be marketed under another project's trademark.

## Capture log

Observed fixtures live under `tests/fixtures/`, each recording the device,
firmware, radio parameters, and capture method. The structural analysis of a
capture (field numbers and wire types present) is recorded without asserting
semantics until the reconstruction process above is followed.
