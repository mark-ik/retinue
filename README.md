# retinue

An endpoint-scoped Rust implementation of the
[Reticulum](https://reticulum.network/) protocol: identity, announces, links,
resources, request/response, and a reliable byte stream, built for embedding as
a library. Live-interoperable with RNS 1.4.0.

**Status: working, wire-verified, pre-1.0.** Not the reference implementation,
and not yet hardened for adversarial deployment (see *Maturity* below). The plan
and wire notes live in [`design_docs/`](design_docs/).

## What works

Every layer below is implemented and checked against a black-box RNS oracle
(never read). The committed byte fixtures under [`tests/fixtures/`](tests/fixtures/)
retain their observed RNS 1.3.8 provenance; the live mixed-runtime gates pass
against the current RNS 1.4.0 pin:

- **Wire vocabulary** — identities, hashes, destination naming, the packet
  codec, announces (including ratchets), and the encrypted token. Sans-io: pure
  functions over bytes, replayable against fixtures.
- **Links** — the handshake (ephemeral ECDH + the mode/MTU trailer), the link
  id derivation, encrypted link data, keepalives, and the request/response and
  resource contexts.
- **Resources** — the advertisement, windowed segmented transfer, and the
  hash-map/proof derivations, plus endpoint-level publish/fetch sessions with
  retry and timeout policy.
- **Reliable streaming** — RNS `Channel`/`Buffer` framing with a dynamic send
  window, plus link-proof acknowledgement, wired into an `AsyncRead + AsyncWrite`
  stream. Opt-in over the best-effort stream (which is right for TCP), for lossy
  media. See [`src/reliable.rs`](src/reliable.rs).
- **The endpoint runtime** — a tokio shell (behind the `tokio` feature, on by
  default) that attaches interfaces, routes inbound packets, opens and accepts
  links, and surfaces them as streams. Turn the feature off and the codec,
  framing, and reliability machinery still stand alone.
- **Transport-node routing** — opt-in (`enable_routing`). The default posture is
  endpoint-scoped — a retinue accompanies a peer — but a node can forward
  announces and link traffic between its interfaces when asked to.

## Maturity

Honest about what is *not* done, so nobody deploys it expecting more:

- **Interfaces**: TCP, the raw interface seam, and an optional Tulle packet-radio
  pump are implemented. RNode serial and direct-PHY USB framing remain owned by
  Tulle. A headed endpoint exchange through two RNode 1.86 radios now covers a
  2 KiB reliable stream and a 4 KiB Resource byte-exactly. UDP is not implemented.
- **Radio MTU**: link MTU, reliable in-flight window, setup retry interval, and
  Resource request window are caller settings. Reliable chunks, Resource parts,
  advertisements, and hashmap updates derive their size from the selected link
  MTU. The current headed profile uses MTU 255 and one frame/part per half-duplex
  turn. Per-interface automatic MTU selection is not implemented.
- **Routing**: route expiry, announce-rate budgeting, owned-destination path
  responses, and transport forwarding are implemented. Open-network hardening
  and announce-cache responses on behalf of other nodes remain outstanding.
- **Reliable interop**: both link directions use the captured IDENTIFY exchange,
  including bounded retransmission under loss. The complete reliable and Resource
  exchange through the Tulle radio pump passed on 2026-07-22; see
  `design_docs/2026-07-22_tulle_headed_acceptance.md`.

The runtime has had a first hardening pass (OS-CSPRNG link entropy, link-setup
DoS and leak fixes, bounded network intake, cancellable teardown), but has not
been audited. Treat it as pre-1.0.

## Provenance

Implemented from the public-domain Reticulum protocol specification and manual,
and the MIT-licensed Beechat `reticulum` crate. The Python reference
implementation was never read — it is used strictly as a black-box oracle, run
and observed. Wire notes: `design_docs/2026-07-13_rns_wire_format_reference.md`.
Not affiliated with the Reticulum project.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same terms.
