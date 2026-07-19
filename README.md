# retinue

An endpoint-scoped Rust implementation of the
[Reticulum](https://reticulum.network/) protocol: identity, announces, links,
resources, request/response, and a reliable byte stream, built for embedding as
a library. Wire-compatible with RNS 1.3.x.

**Status: working, wire-verified, pre-1.0.** Not the reference implementation,
and not yet hardened for adversarial deployment (see *Maturity* below). The plan
and wire notes live in [`design_docs/`](design_docs/).

## What works

Every layer below is implemented and checked byte-for-byte against RNS 1.3.8,
which is run as a black-box interoperability oracle (never read) with its output
captured as fixtures under [`tests/fixtures/`](tests/fixtures/):

- **Wire vocabulary** — identities, hashes, destination naming, the packet
  codec, announces (including ratchets), and the encrypted token. Sans-io: pure
  functions over bytes, replayable against fixtures.
- **Links** — the handshake (ephemeral ECDH + the mode/MTU trailer), the link
  id derivation, encrypted link data, keepalives, and the request/response and
  resource contexts.
- **Resources** — the advertisement, windowed segmented transfer, and the
  hash-map/proof derivations.
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

- **Interfaces**: TCP and an in-memory loss oracle only. Serial/KISS, RNode, and
  UDP are the R10 work; there is no radio yet (see the Heltec/RNode doc in
  `design_docs/`).
- **Resources at the endpoint**: the resource codecs and state machines work and
  are tested, but the endpoint exposes no resource-transfer driver or
  publish/fetch API yet.
- **Routing**: no route expiry, announce-rate budgeting, or path-request
  responses. Fine for a small trusted mesh, not the open network.
- **Reliable interop with an RNS initiator**: a retinue *responder* proves with
  its identity (validated via the announce), which RNS accepts; a retinue
  *initiator*'s proofs need an `identify`-over-link step still to come.

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
