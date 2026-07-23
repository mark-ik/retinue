# sennet

An independent, permissively licensed mesh radio protocol implementation in
the [retinue](https://github.com/mark-ik/retinue) family, targeting
interoperability with existing LoRa messaging meshes, on the shared
[tulle](https://github.com/mark-ik/tulle) radio layer.

Sennet is an independent implementation, developed from wire observation and
public documentation. It is not affiliated with or endorsed by any existing
mesh project.

A sennet is a ceremonial fanfare for a procession.

**Status:** the client serial deframer, schema-free protobuf reader, direct
capture fixtures, LoRa transport header/AES-128/256-CTR layer, application
envelope, port-1 UTF-8 text path, caller-persisted source/packet-ID allocator,
and bounded managed-flood relay core are implemented. The relay filters one
configured channel, deduplicates `(source, packet_id)`, preserves ciphertext and
nonce identity, and returns a configurable delay window to its caller. A Sennet
text packet built through that API was transmitted by Tulle direct-PHY firmware
on COM6, accepted and rebroadcast by a stock node on COM7, and returned through
COM7's client API. The exact RF packet and client receipt are regression
fixtures.

With the `hardware` feature, `direct_phy_text` drives that same path through
Tulle's reusable Rust serial link. It advances and flushes a versioned packet-ID
state file before transmitting. The protocol layer constructs and opens
packets; Tulle owns USB framing, pacing, and radio metrics.

Reconstruction follows controlled radio-bench experiments, with raw captures
and the scope of each claim recorded in [`PROVENANCE.md`](PROVENANCE.md).
Unexplored fields remain numbered rather than acquiring speculative names.

The source crates remain MIT/Apache-2.0. Downstream combined firmware may be
distributed under GPLv3 with its corresponding source and required notices;
GPL-derived implementation code does not enter the permissive crate graph.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
