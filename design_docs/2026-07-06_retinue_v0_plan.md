# retinue v0 — Endpoint-Scoped Reticulum

**Status (2026-07-15):** **R0–R7 done and R5 (mere adoption) landed — retinue now
backs mere's `Transport` trait, all verified against a live RNS 1.3.8.** retinue holds
an identity; builds and validates announces (ratcheted and not); frames HDLC; exchanges
announces over live TCP both ways; learns peers into an address book and emits path
requests; is a full encrypted-link peer in both roles (data both ways, keepalive,
teardown, request/response); does resources end to end both ways incl. 2.5MB
multi-segment (RNS concludes COMPLETE); is a full RNS-compatible transport node
(routing verified both directions); and runs an **endpoint that exposes links as
`AsyncRead + AsyncWrite` streams**, proven bidirectional against RNS. 63 retinue tests
+ fixture/framing suites green, plus **live mixed-runtime interop gates** (announce,
link initiate/respond, request/response, R2 path, resource both ways, routing both
ways, endpoint stream). **R5 mere wiring is done**: `ReticulumTransport` runs on
`retinue::endpoint::Endpoint`; mere's reticulum-lane tests pass (bilateral round-trip
included) and the Beechat pin is deleted. Remaining: R4 follow-ons (dynamic window
sizing, retries/cancel) and the R8–R10 spec-parity phases (IFAC, full ratchets,
remaining interface types).
Direction decided in the Mere workspace (mere design_docs,
`2026-06-29_reticulum_transport_plan.md` Direction section and
`2026-07-06_lxmf_key_addressed_mail_research.md`): Mere stewards its own
implementation rather than depending on Beechat's stale 0.1.0 or FreeTAK's
daemon-shaped EPL stack. The Reticulum protocol is public domain; upstream
reference-implementation stewardship is in flux (license change April 2025,
founder stepped back December 2025, community forks).

## Goal

A library crate implementing the Reticulum protocol, wire-compatible with RNS 1.3.x:
hold an identity, announce it, resolve peers, establish links, exchange packets and
resources, **and route** (act as a transport node: path table, announce propagation,
packet forwarding, link transport). Embedding is the product; the first consumer is
Mere's `transport` crate behind its `Transport` trait, replacing the Beechat pin
(deterministic identity from a seed, announce-bound peer ids, ALPN-to-destination
mapping, bilateral streams). Routing (in scope as of 2026-07-15) additionally lets a
retinue node carry traffic for a small mesh, not only accompany one peer.

## Scope change 2026-07-15: full RNS protocol parity

Mark decided routing, and the whole Reticulum protocol spec, is in scope. retinue is
no longer endpoint-scoped: the target is a complete RNS transport stack — identity,
announce, link, resource, **transport-node routing** (path table, announce
propagation, packet forwarding, link transport), **IFAC**, full **ratchet** handling,
and the remaining **interface types** over time. The endpoint work (R0–R5) is the
foundation; routing and the other full-spec items are the phases beyond it.

Boundary that still holds: "the spec" means the **Reticulum protocol** (transport +
destinations + links + resources + identity + interfaces, per reticulum.network/manual).
**LXMF stays out** — it is an application/message layer *above* Reticulum, a separate
`lxmf`-shaped sibling if ever wanted, not part of the RNS stack.

Open: the **name**. "retinue" was chosen to encode the endpoint-only, non-routing
stance ("accompanies one peer, does not carry others' traffic"). With routing in
scope that rationale no longer fits. Flagged for Mark; not renamed unilaterally.

## Non-goals (revised)

- **LXMF and application/message layers.** Above the RNS stack; a separate sibling.
- **Daemon.** No standalone process by default; library embed first. (A `rnsd`-style
  transport-node binary becomes plausible once routing lands, but it is not the
  default shape.)

## Reference discipline

- Implement from the **public-domain protocol specification and manual**
  (reticulum.network/manual). Pin the manual version each phase works against.
- The Python reference is a **black-box interoperability oracle**: mixed-runtime
  smoke tests against `rnsd`/reference tools. Its code is not read (its license
  carries post-2025 clauses; the oracle posture also keeps behavior questions
  honest, answered by wire observation rather than code imitation).
- Beechat `Reticulum-rs` (MIT) may be read freely; FreeTAK `reticulum-rs`
  (EPL-2.0) is technique-only, never copied text.
- Crypto comes from RustCrypto/dalek crates (X25519, Ed25519, AES, HKDF,
  HMAC-SHA256); this crate implements framing and token formats, never
  primitives.

## Phases

- **R0 — primitives + wire vocabulary. DONE 2026-07-13.** Dual-key identity
  (X25519 + Ed25519), destination hashing and name hashing, packet encode/decode,
  the encrypted token format, announce structure + validation. The oracle harness
  came first, as planned, and it earned its keep immediately: it overturned two
  things the paper research had inferred (see the wire reference, section 0).
  Done: 20 tests green. retinue validates every announce RNS emits, retinue's
  announces are byte-identical to RNS's from the same inputs (including ratcheted
  ones), retinue decrypts tokens RNS encrypted to it, and retinue rejects all six
  corrupted-announce fixtures. Fixtures committed under `tests/fixtures/`, so CI
  needs no Python.
- **R1 — TCP interface. DONE 2026-07-13.** HDLC framing (sans-io, in
  `iface::hdlc`) and a tokio shell over it (`iface::tcp`, behind the default
  `tokio` feature; turn it off and the codec still stands alone).
  Done: the live gate passes. `oracle/interop_r1.py` stands up a real RNS with a
  `TCPClientInterface` pointed at retinue and checks both directions. **RNS
  accepts an announce retinue built, signed and framed** (its own signature
  validation, its own announce handler, app_data intact), and retinue de-frames,
  decodes and validates RNS's announce over the same socket. The framing itself
  was captured, not assumed: `0x7E` flag, `0x7D` escape, XOR `0x20`, and *both*
  special bytes escaped, which was settled by announcing `app_data` full of them
  and reading the wire.
- **R2 — endpoint announce/path behavior. DONE 2026-07-13** (endpoint parts).
  Announce cadence, receipt, address-book resolution, and path-request emission.
  - `src/address_book.rs`: ingests validated announces (keyed by destination hash)
    and resolves a destination to its identity and current ratchet. This is what a
    link needs. Tested against the committed announce fixtures.
  - `src/path.rs`: builds a path request, a plain data packet to
    `rnstransport.path.request` carrying `target(16) || tag(16)`. The plain
    destination hash and the packet layout are known-answer tested against a capture
    of `RNS.Transport.request_path`. `DestinationName::plain_hash` handles the
    identity-less plain form.
  - Cadence is `tokio::time::interval` + `announce::build` in the shell; the R2 gate
    demonstrates it.

  The gate passes (`oracle/interop_r2.py`): against a transport-enabled RNS, retinue
  announces itself, emits a path request RNS accepts, re-announces on cadence, and
  resolves the target from a real RNS announce into its address book.

  Scope note: the plan's original done-condition names a *two-hop* resolve through a
  transport node. In a direct single-interface connection (retinue's actual use in
  mere, and this gate) announces propagate directly, so the path request is not
  strictly required to resolve; forcing a path-request-only resolve needs a
  two-transport-node topology. retinue's own R2 responsibilities, emit announces on
  cadence, ingest announces, and emit well-formed path requests, are all implemented
  and verified against real RNS. The relay itself is RNS transport behaviour, not
  retinue code, so it is not gated here.
- **R3 — links. ESTABLISHMENT + CHANNEL DONE 2026-07-13.** Link establishment
  (request, proof, key derivation) and the encrypted data channel, in `src/link.rs`.
  Done: the live gate passes (`oracle/interop_link.py`). retinue's own code opens a
  link to a real RNS 1.3.8, RNS decrypts application bytes retinue encrypted on the
  link, retinue decrypts RNS's reply, and the link survives an idle period. Also a
  deterministic fixture test (`tests/link_session.rs`) reproduces the whole
  derivation and decrypts captured RNS link data with no Python.

  The crypto was pinned by a known-secret initiator probe before any Rust was
  written, and this time Beechat's model held up. Key facts:
  - Request: `ephemeral_x25519(32) || ephemeral_ed25519(32) || trailer(3)`.
  - Proof: `signature(64) || peer_ephemeral_x25519(32) || trailer(3)`, context
    `0xff`, signature over `link_id || peer_eph_x || peer_identity_ed25519 ||
    trailer`. Cross-checked: retinue's link id equals RNS's own
    `link_id_from_lr_packet`.
  - Session key: `HKDF-SHA256(ikm = ECDH(ephemerals), salt = link_id, info = empty)`,
    then the R0 token with **no** ephemeral prefix (static per-link key). It is
    literally `token::DerivedKeys` with `salt = link_id`.
  - **Links carry no ratchet.** The forward secrecy already lives in the ephemeral
    exchange, so the ratchet machinery that breaks Beechat on announces does not
    touch the link channel. RTT (context `0xfe`) moves the link to active on the
    peer.

  **Responder side DONE 2026-07-13.** `link::accept` proves an inbound request, and
  `Link::receive` classifies inbound traffic (data, RTT, keepalive request/response,
  close). The responder gate passes (`oracle/interop_link_responder.py`): RNS
  initiates a link to retinue, retinue proves it (RNS validates the proof and
  establishes, confirming retinue's signing and derivation), they exchange encrypted
  bytes both ways, a keepalive round-trips, and retinue recognises the teardown.

  R3 is functionally complete for a link peer: both roles, encrypted channel both
  ways, keepalive, teardown.

  **Request/response DONE 2026-07-13.** Captured, then implemented in `src/request.rs`.
  RNS layers a thin request/response protocol on the link data channel:
  - request  = msgpack `[time_f64, path_hash(16), data]`, context `0x09`;
  - response = msgpack `[request_id(16), data]`, context `0x0a`;
  - `path_hash = trunc16(SHA256(path))`, and `request_id` is the request packet's
    hash: `trunc16(SHA256(masked_flags || dest || context || ciphertext))`, RNS's
    generic packet hash, now on `Packet::hash`.

  retinue treats request and response data as opaque bytes (RNS can carry any msgpack
  value; a consumer layers its own structure), which keeps retinue a transport. The
  gate passes both ways (`oracle/interop_reqresp.py`): retinue requests `/echo` from
  RNS and matches the response by id, and RNS requests `/svc` from retinue and gets
  retinue's answer. A minimal purpose-built msgpack codec handles exactly these two
  shapes; no msgpack dependency was added.

  **R3 is now complete.**
- **R4 — resources. COMPLETE 2026-07-15, both directions, multi-megabyte.** The
  full windowed transfer state machine, verified against real RNS with a **2.5 MB
  multi-segment resource that round-trips intact both ways** (RNS concludes
  COMPLETE). Done-condition met. What landed on top of the receiver base below:
  - **bz2 compression** (default-on `compression` feature, pure-Rust `libbz2-rs-sys`,
    no C toolchain). retinue decompresses RNS's own bz2 and RNS decompresses retinue's.
  - **windowed part requests + hashmap updates (HMU)**: request
    `0x00 || hash || wanted*`; exhausted solicit
    `0xff || last_map_hash(4) || hash || wanted*` (the leading hash tells the sender
    where the HMU resumes); HMU (ctx 0x04, sealed)
    `resource_hash(32) || msgpack([segment, hashmap_bin(4*M)])`. `HASHMAP_MAX_PARTS = 74`
    per advertisement; the receiver grows a window.
  - **segmentation** above `MAX_SEGMENT_SIZE = 1048575`: each segment its own
    advertisement (`i` = 1-based index, `l` = total, `d` = total data size), all
    sharing one `original_hash` (segment 1's hash) so the receiver groups them; the
    receiver proves each segment and concatenates the recovered bodies.
  - `src/resource.rs`: `Incoming` (windowed receiver), `Outgoing` (windowed sender,
    `with_segment`), `Request`/`Hmu` codecs, `parse_proof`. Self-contained unit tests
    round-trip windowed and multi-segment transfers with no RNS.

  Gates: `interop_resource_recv.py` (2.5 MB / 3 segments received, HMU, RNS COMPLETE),
  `interop_send_multiseg.py` (2.5 MB / 3 segments sent, RNS COMPLETE), plus the
  compressed and single-segment send gates. 42 tests green.

  **Deferred R4 optimizations (tracked, not needed for interop over reliable links):**
  1. **Dynamic window sizing.** RNS grows the request window with throughput
     (`WINDOW` 4 → `WINDOW_MAX`/`WINDOW_MAX_FAST` 75, stepped by the `RATE_FAST`/
     `VERY_SLOW_RATE` thresholds). retinue requests all currently-known missing parts
     at once (an unbounded window). Fine on TCP/loopback; matters for flow control on
     slow or lossy links. To add: cap the per-request window and grow it on observed rate.
  2. **Retries and cancellation.** retinue does not retransmit a lost part or a lost
     HMU, and does not emit/handle `RESOURCE_ICL` (0x06, initiator cancel) or
     `RESOURCE_RCL` (0x07, receiver cancel). RNS uses `MAX_RETRIES = 16` and
     `PART_TIMEOUT_FACTOR` for part timeouts. Needed for reliability on lossy media
     (LoRa/serial); invisible over TCP. To add: per-part/HMU timeout + re-request, and
     the two cancel contexts.

  Historical notes (how it was built): protocol reversed 2026-07-13; the advertisement
  is a msgpack map with transfer/data sizes, part count, resource/original hashes, a
  per-part hashmap, and flags.

  **Advertisement codec DONE 2026-07-13.** `src/resource.rs` parses and builds the
  advertisement map, with its own small msgpack map codec (fixmap, uint, int, nil,
  bin, single-letter str keys). It re-packs the real captured advertisement to the
  exact bytes, key order included, which is the proof it is faithful.

  **Derivations solved and receiver DONE 2026-07-14, verified live.** All the
  RNS-specific pieces were black-box extracted from a live `RNS.Resource`:
  - resource hash = `SHA256(data || random_hash)`; map hash = `SHA256(part ||
    random_hash)[..4]`; proof = `SHA256(data || resource_hash)`.
  - the transferred **content is `random_hash || data`**, then optionally bz2, then
    sealed as one link token, then split into `SDU = 464` parts. Flags: bit0 = encrypted,
    bit1 = compressed.
  - the windowed request is `flag(0x00) || resource_hash(32) || requested map_hash(4)*`;
    the receiver answers with the exact parts named.
  - the proof is a **Proof-type** packet on the link, context `RESOURCE_PRF`, payload
    `resource_hash(32) || proof(32)`, sent unencrypted.

  `src/resource.rs` implements the sender helpers and the `Incoming` receiver state
  machine (single-segment). The **receive gate passes**
  (`oracle/interop_resource_recv.py`): RNS sends an uncompressed resource, retinue
  requests the parts, reassembles, decrypts, strips the random-hash prefix, verifies
  against the resource hash, and returns the proof; **RNS concludes COMPLETE**.

  (Resolved during completion: the sender's proof capture needed RNS's `ACCEPT_APP`
  in-RAM strategy; `ACCEPT_ALL` routed received resources through a disk path the
  ephemeral test config could not satisfy.)

  Tooling: `oracle/capture_resource*.py`, `interop_resource_recv.py`,
  `examples/resource_{probe,recv,send_probe}.rs`.
- **R5 — Mere adoption. DONE 2026-07-15. `ReticulumTransport` runs on retinue and
  mere's reticulum-lane tests pass; the Beechat pin is gone.**
  `mere/crates/murm/transport/src/reticulum_transport.rs` was rewritten over
  `retinue::endpoint::Endpoint`: the builder derives the retinue identity from
  mere's master seed (HKDF-SHA256, `keys.rs`), registers one destination per ALPN,
  and runs three background tasks over an `Arc<Endpoint>` — an accept router
  (dispatch `accept_on_any` inbound links to per-ALPN queues by destination), an
  announce listener (`next_announcement` → verify the master-signed app_data
  binding → record `PeerID → identity`), and a periodic announce sender. `connect`
  resolves a peer's retinue identity from the learned map and calls
  `Endpoint::open`; `accept` reads its ALPN queue; the stream is a thin newtype
  over `LinkStream`. All 3 acceptance tests pass (stable peer-id / derived
  identity, `AlpnNotRegistered` on unregistered accept, and a full bilateral
  round-trip over TCP loopback — client links to server and exchanges hello/world),
  and the whole `mere-transport` suite is green (32 tests) with the default
  (no-feature) build unaffected. The `reticulum = "0.1"` Beechat pin is replaced by
  `retinue = { path = "../retinue" }`.

  **Dependency-resolution finding (drove two retinue-side pins).** retinue had
  adopted the bleeding-edge RustCrypto/dalek line (ed25519/x25519-dalek 3.0.0,
  sha2 0.11 / hkdf 0.13 / hmac 0.13). iroh 0.98 (reached transitively through
  mere's p2panda-net) pins the *same* prerelease line but with exact `=` pins:
  `ed25519-dalek =3.0.0-pre.6`, `sha2 =0.11.0-rc.5`. A caret `^3.0.0` (final) and an
  exact `=3.0.0-pre.6` are both "major-3" so Cargo can neither unify them nor split
  them into separate copies — a hard resolution failure. Fix: pin retinue's crypto
  to the *stable* line (dalek 2.x, sha2 0.10 / hkdf 0.12 / hmac 0.12), which is
  major/minor-*incompatible* with the prereleases and so resolves to a clean
  separate copy — exactly how the old Beechat probe (dalek 2.x) coexisted. Crypto
  output is byte-identical, all 63 retinue tests stay green, and the only code
  churn was one import (`hmac::KeyInit` → the `Mac` trait's `new_from_slice`). The
  unused `rand_core` dep was dropped. Retinue commits: endpoint `&self` (shareable),
  dalek 2.x pin, digest-family pin.

  ---
  *Original R5 plan (for reference):* The seam mere implements its `Transport`
  trait against is built and RNS-verified:
  `src/endpoint.rs` is a working endpoint that establishes encrypted links and
  exposes them as `AsyncRead + AsyncWrite` `LinkStream`s. The endpoint stream gate
  passes (`oracle/interop_endpoint_stream.py`): retinue accepts an inbound link as a
  stream, reads RNS's bytes, and echoes them back over raw link data, the exact lane
  mere uses. The endpoint also surfaces validated announces
  (`Endpoint::next_announcement`, carrying app_data) and destination-tagged accepts
  (`accept_on_any`), which are the hooks a host needs for peer-id binding and
  per-ALPN dispatch.

  The central R5 claim is proven: retinue does full two-way announce, link, stream,
  and (receive-side) resource interop with real RNS 1.3.8, ratchets and all, which is
  more than the Beechat probe ever did.

  **The remaining mere wiring** is a cross-repo integration in `mere/crates/murm/
  transport`:
  1. `RetinueTransport` implementing `Transport` over `Endpoint`: derive the retinue
     identity from mere's master seed (HKDF, as the old `keys.rs` did); bind mere's
     `PeerID` to the retinue identity via signed announce app_data (mere cannot derive
     a peer's HKDF'd identity from its Ed25519 PeerID, so this binding is mandatory,
     learned via `next_announcement`); map ALPN → `DestinationName`; `connect`/`accept`
     over `Endpoint::{open, accept_on_any}`, wrapping `LinkStream` as `Transport::Stream`.
  2. Carry over the probe's tests; delete the Beechat `reticulum = "0.1"` pin.

  **Architectural note found during R5:** the current `Endpoint` is point-to-point (one
  interface connection), which is all the RNS gates and a first mere lane need. A
  production mere transport reaching many peers wants the endpoint extended to attach
  to shared interface(s) and hold many links, the shape the Beechat `ReticulumStack`
  had. That extension, plus the mere wiring above, is the focused follow-up; it needs
  the heavy mere workspace build in view (toolchain, iroh/p2panda, the reticulum
  feature) and retinue as a path/git dependency.

  Done-condition unchanged: Mere's reticulum-lane tests pass on retinue with the
  Beechat dependency deleted.

## Full-spec phases (added 2026-07-15, beyond the endpoint foundation)

These follow R0–R5 and bring retinue to RNS protocol parity. Sequencing is a
proposal, not fixed.

- **R6 — multi-interface endpoint. DONE 2026-07-15.** `Endpoint::new` +
  `attach_tcp_client` / `listen_tcp` (accept loop, one interface per connection). Every
  interface's reader feeds one router channel tagged with the interface; a per-interface
  writer drains its own outbound. Announces broadcast to all interfaces; a link binds to
  the interface it came in on. Integration test: a hub with two interfaces reaches two
  leaves independently (echoes uncrossed).
- **R7 — transport-node routing. DONE 2026-07-15, RNS-interop both ways.** retinue is a
  fully functional, RNS-compatible transport node.
  - **Leaf side** (retinue routes *through* a transport node): a header-type-2 announce
    teaches an interface's next-hop transport node (its identity hash, in the transport
    field). Packets out such an interface are addressed header-type-2 `[transport][dest]`.
    Verified live: a retinue leaf reaches a peer two hops away through a real RNS
    transport node (`oracle/capture_link_forward.py`) — the original R2 done-condition.
  - **Node side** (retinue forwards): announce propagation (stamp header-type-2 with our
    id, hops+1, dedup by packet hash, hop limit); a packet whose destination is a link we
    bridge forwards to the opposite interface whatever its header type (the key subtlety:
    a responder that never learned it is behind us replies header-type-1, and we must
    still forward it back); a header-type-2 packet addressed to us forwards toward its
    destination by the path table, recording a link-transport bridge for link requests.
    Verified live: a real RNS node routes through a retinue transport node
    (`oracle/interop_transport_node.py`) — link + echo.
  - Primitives that made it cheap: header-type-2 codec, `Packet::hash`, announce parsing,
    the address book (all pre-existing).
  - Deferred (non-essential): the ~2% announce-bandwidth cap and path-request *responses*
    (retinue emits path requests; answering them is a transport-node nicety, not needed
    for the above); path/link-transport table expiry.
- **R8 — IFAC.** Interface access codes: derive the shared Ed25519 signing identity
  from a passphrase/network name, sign every outbound packet, verify + drop on inbound.
  1–64-byte codes. retinue already decodes the IFAC flag.
- **R9 — ratchet encryption.** Encrypt single packets to a destination's current
  ratchet (retinue already parses + stores ratchets from announces); ratchet rotation
  and retention. Forward secrecy for the asymmetric-packet path.
- **R10 — remaining interfaces.** Serial/KISS, RNode, UDP, and the others, behind the
  same interface seam as TCP. The Heltec/RNode route, embedded Rust boundary,
  and stock-firmware versus Rust-firmware sequencing are specified in
  [`2026-07-19_heltec_rnode_and_embedded_rust.md`](2026-07-19_heltec_rnode_and_embedded_rust.md).
- **Still out:** LXMF and application/message layers (separate sibling).

## On-air readiness — the pre-R10 gate (added 2026-07-17)

Prompted by an external roadmap review and verified against the tree. Five items
are filed across R4, R7, and the open questions as independent "pick up whenever"
deferrals. **They are not independent.** Each was deferrable for one reason — TCP
hid it — and each comes due the moment a lossy, shared-airtime interface (LoRa via
RNode, serial) lands. They are **one milestone, and R10 is its trigger, not its
peer.** None of it is needed while TCP is the only interface; all of it is needed
before the first packet goes on air.

The five, and why TCP hid each:

1. **Link reliability** (was an open question, "decide at R3" — decided by default
   when R5 shipped `LinkStream` into mere's `Transport`). RNS link data packets are
   unsequenced best-effort; retinue's `LinkStream` sends raw `data_packet`s with no
   sequence number or retransmit, and there is **no `Channel`/`Buffer` layer in the
   tree** (verified). On TCP the transport delivers in order, so it is invisible. On
   LoRa, `poll_write` returns `Ok(n)` on a link that silently drops parts — a `std`
   `AsyncWrite` returning `Ok` for bytes that never arrive is a trait lying to its
   caller, and **mere is already that caller.** Correct today only because the sole
   interface is reliable; a latent correctness bug, not a live one.
   - **Resolution: implement RNS `Channel` + `Buffer`, not a bespoke shim.** Raw
     link data is best-effort *by spec* — retinue is faithful there. RNS's own
     reliable stream is a separate layer: `Channel` (sequenced, windowed, retried)
     with `Buffer` for stream I/O on top. Back `LinkStream` with `Buffer`/`Channel`
     and mere's stream becomes reliable over any medium **transparently, no API
     change**. This supersedes the old "sequence-it vs reliable-interfaces-only"
     open question — RNS already answers it.
2. **R4 dynamic window sizing.** Flow control on slow/lossy links; a fixed window
   wastes airtime or overruns a slow peer.
3. **R4 retries + cancellation.** Reliability on lossy media; invisible over TCP.
   Folds into the Channel/Buffer work — that is where retries live.
4. **R7 announce bandwidth cap (~2%).** On fixed TCP topology, forwarding announces
   without a budget costs nothing anyone notices. On shared airtime, airtime is
   *the* scarce resource: an uncapped transport node degrades the channel for
   everyone on it, and RNS's own machinery penalizes exactly that.
5. **R7 path / link-transport table expiry.** TCP topology does not move, so a stale
   next-hop is harmless. Radio moves; a stale path table blackholes traffic toward a
   peer that has gone. Mandatory the moment the topology can change under you.

**One correction to the review, and it cuts the other way:** it called the R10
interface "the cheap part — KISS mostly written in `iface::hdlc`." Not quite.
retinue has **HDLC** (0x7E flag byte-stuffing); **KISS** is different bytes (FEND
0xC0 / FESC 0xDB), plus command framing, plus the RNode-specific opcodes
(rnodeconf). The pattern transfers; the code mostly does not. The trigger is a bit
more than a rename of the deframer — which only sharpens the point that on-air is a
real milestone, not a flag-day.

**Sequencing:** resolve link reliability (Channel/Buffer) **before** R10 — it is a
correctness contract mere already leans on, cheaper to settle now than after a lossy
interface exposes it. The four airtime/flow items (2–5) may land with R10 but must
all be present before any on-air *deployment*; none is optional on a shared channel.

**Exit criterion:** on R10 completion (retinue genuinely on-air capable), **update
the README** — it currently describes a TCP-only endpoint and must reflect
LoRa/RNode/serial and the on-air posture.

### Sharpened by the review's reply (2026-07-17)

Two corrections to the framing above, both right:

- **Channel/Buffer does not *leave* the on-air bucket — it joins it.** Naming the
  right artifact (RNS `Channel`/`Buffer`, documented in the manual; sources sit in
  the oracle venv, unread) does not move the work. A retry/window/timeout layer's
  entire value is in its loss paths, and the oracle is Python RNS over **TCP
  loopback** — it never drops, reorders, or delays. Implement Channel against it and
  every retry branch is dead code that passes because it never runs: a green gate
  proving Channel works on the one medium where Channel is unnecessary. The
  "dissolves it" framing above was wrong; it is a healthier *name* for the work, not
  less work.
- **So the first build is the lossy oracle, and it needs no hardware.** A
  deterministic drop / reorder / delay shim on the interface seam, **seeded so
  failures reproduce**. That is the prerequisite for building Channel, retries,
  cancellation, dynamic window sizing, and part timeouts *correctly*. Most of the
  on-air milestone is desk work, blocked today only by the absence of a medium that
  misbehaves — a few hundred lines, not a radio. **This is the next build.**

**The one piece that genuinely needs hardware.** The reference discipline names RNS
Python (barred), Beechat (MIT, free), FreeTAK (EPL, technique-only) — and says
nothing about **RNode_Firmware**, which is **GPLv3** and the only complete current
normative definition of the RNode serial behavior. The manual documents
RNodeInterface's config *options* (frequency, bandwidth, spreading factor) but not
the current opcode payloads and state transitions that apply them. An original
RNode hardware page publishes a legacy command table, but it does not specify the
complete RNode 1.86 session, errors, multi-radio behavior, or long-packet behavior.
No complete public-domain source exists. So R10's RNode half is the first phase where
capture needs a **physical board on USB**, black-boxed the way `rnsd` has been. That
is a procurement lead time and a policy note, not a coding task, and it is the
*only* part of the milestone gated on hardware.

**KISS, precisely** (correcting the correction): not just different constants. HDLC
unescapes by XOR (`0x7D`, then `byte ^ 0x20`); KISS unescapes by transposition
(`0xDB 0xDC → 0xC0`, `0xDB 0xDD → 0xDB`), adds a command byte after `FEND` (high
nibble port, low nibble command), and hangs RNode's opcodes off `SetHardware`. The
deframer's *shape* survives; the operation doesn't. Reusable part: "you've written a
deframer before."

*Credit: this section is a three-round exchange with an external reviewer — the
five-into-one decomposition and the Channel-joins-the-bucket / lossy-oracle
sharpening are theirs; the Channel/Buffer naming and the KISS/HDLC mechanics are
retinue's. The lossy oracle is the agreed next build; the RNode board is the agreed
procurement.*

**2026-07-19 update:** current stable RNode Firmware 1.86 now explicitly lists
Heltec LoRa32 V3, V4, and T114. Hardware is still required for a black-box opcode
capture under the provenance policy above, but board support is no longer an
unknown. The firmware direction is a separate, independently authored
MIT/Apache Rust radio workspace, not a GPL source port. Shared board, SX1262,
scheduler, settings, and capacity crates support distinct RNode-compatible,
native Retinue, and Meshtastic-compatible firmware images. The host capture must
land and be tagged before permissive compatibility work begins. After that
oracle, the protocol personalities can proceed in parallel; the modem is not a
prerequisite for removing the host. The lanes and gates are separated in
[`2026-07-19_heltec_rnode_and_embedded_rust.md`](2026-07-19_heltec_rnode_and_embedded_rust.md)
and refined by
[`2026-07-19_modem_embedded_and_meshtastic_research.md`](2026-07-19_modem_embedded_and_meshtastic_research.md).

## Decisions (2026-07-13)

**Version pin: RNS 1.3.8, and the 1.x churn does not threaten us.** Upstream is
still shipping under `markqvist/Reticulum` (1.3.8 on 2026-07-10; 1.1.9 → 1.3.8
in under three months), so "the founder stepped back" describes community
engagement, not releases. The moving parts in that window are transport-node
machinery: 1.2.5 added path-request ingress/egress control, 1.3.8 added an
`internal` interface mode and fixed a hop-count serialization error on
transport. All of it sits in the routing layer retinue declares a non-goal. The
endpoint wire (identity, announce, link, resource) is the stable core, and both
community forks (RetiNet, Reticulum_CE) claim RNS 1.0 compatibility, which is
the best available evidence that the 1.x endpoint format is frozen. Pin the
oracle venv to `rns==1.3.8` and the manual to the 1.3.8 snapshot; re-pin on a
schedule, not on every upstream release.

**Async posture: sans-io core, tokio shell.** It falls out of R0 naturally, as
the plan hoped. R0 is entirely pure functions over bytes (identity derivation,
name and destination hashing, packet encode/decode, token format, announce
validation), so the core needs no runtime and the oracle fixtures can be
replayed against it with no async at all. The shell is not optional, though:
Mere's `Transport` trait requires `Send + Sync` with an associated
`Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static` and `impl Future +
Send` returns, so R1 onward is tokio. Keeping the codec runtime-free also keeps
the later serial/RNode/LoRa interfaces open.

**Oracle in CI: fixtures yes, live oracle no.** Commit the oracle-generated
fixtures and replay them in CI, where they need no Python. The live
mixed-runtime interop run (retinue against a real `rnsd`) stays a local gate,
like Mere's headed-verify harness. CI keeps regression value on the codec;
the Python dependency stays off the critical path.

## Open questions

- **Ratchets in announces: ANSWERED 2026-07-13.** A 32-byte X25519 ratchet key is
  inserted between `rand_hash` and the signature, signalled by header bit 5 (the
  Context Flag), and covered by the signature. retinue implements it. The
  remaining ratchet question is the *link* half: how a sender selects which
  ratchet to encrypt to, and what a receiver retains (`RATCHET_COUNT = 512`,
  `RATCHET_INTERVAL = 1800`, `RATCHET_EXPIRY = 30 days`). Settle at R3, the same
  way: by capture.
- **Link trailer and link id: ANSWERED 2026-07-13** by `oracle/capture_link.py`.
  A link request is **67** bytes and a proof **99**: both carry a 3-byte trailer of
  `mode(3 bits) | mtu(21 bits)`, big-endian. The initiator asks for AES-256 and MTU
  8192; the responder answers AES-256 and MTU 500. The link id is
  `trunc16(SHA256((flags & 0x0F) || destination || context || payload[..64]))`, with
  `hops` excluded and the trailer deliberately outside the hash. Solved against two
  captured (request, link id) pairs. Encoded in `src/link.rs` with both vectors as
  tests. Caveat recorded there: both samples had `flags == 0x02`, so the `& 0x0F`
  mask is taken on authority, not proven.
- **Still open for R3:** the proof's internal field order (signature-then-key, or
  key-then-signature), which needs the signed pre-image; and the ratchet selection
  rules on links (`RATCHET_COUNT = 512`, `RATCHET_INTERVAL = 1800`, 30-day expiry).
- Whether the link layer gets a reliability shim. RNS link data packets are
  unsequenced and best-effort (see "Lessons from the Beechat probe"). Over TCP
  that is invisible; over LoRa it is not. Decide at R3 whether `AsyncRead`/
  `AsyncWrite` on a link implies retinue sequences and retransmits, or whether
  the stream type is only offered on reliable interfaces.
- **IFAC** (interface access codes) is not derivable from any allowed source:
  Beechat declares the type and never serialises it. retinue currently decodes the
  IFAC flag and ignores the field. Needed only for IFAC-protected interfaces, so
  it can wait, but it must not be forgotten.

## Lessons from the Beechat probe

Mere's `reticulum_transport` (about 1,100 lines across `reticulum_transport.rs`,
`announce.rs`, `keys.rs`, `stream.rs`, `tests.rs`, against `reticulum = "0.1"`)
is a working endpoint. It is also a catalogue of everything the Beechat API
makes hard, and every workaround in it is a requirement on retinue's surface.

1. **Destinations cannot be registered on a shared handle.** `add_destination`
   takes `&mut self`, so the probe keeps the stack owned mutably until every
   ALPN is registered and notes the constraint in a comment, because it becomes
   unreachable once the stack is behind an `Arc`. Retinue registers
   destinations through a shared handle, so a destination can be added after
   bind.
2. **No stream abstraction.** The probe hand-builds one: a tokio `DuplexStream`
   plus two relay tasks, chunking writes into link data packets. Retinue hands
   back a stream type directly (R3).
3. **Link events arrive on a global broadcast channel.** Every consumer
   demultiplexes by `LinkId` and handles `Lagged` itself, in four separate
   places in the probe. Retinue returns a per-link handle that owns its own
   event stream.
4. **Link direction leaks into the caller.** `send_to_out_links` and
   `send_to_in_links` take different address semantics, so the probe carries a
   `LinkSide::{Out, In}` enum purely to remember which side it is on. A per-link
   handle erases the distinction.
5. **Announce matching has a padding trap.** Lookups must key on the 10-byte
   destination name hash slice, never the 32-byte name hash, which is
   zero-padded on the wire and silently fails to match. The probe carries a
   comment warning about it. Retinue keys announces by a real
   `DestinationName` type and never exposes the trap.
6. **Peer resolution is a sleep loop.** `resolve_peer` polls the address book
   every 100ms until `connect_timeout`. Retinue makes resolution awaitable,
   waking on announce receipt.
7. **The caller guesses the MDU.** The probe picks a 1024-byte chunk against a
   2048-byte `PACKET_MDU` because "Fernet framing adds IV + HMAC overhead, so
   1024 leaves comfortable headroom." Retinue exposes the true post-framing
   payload capacity.
8. **Identity construction goes through a hex string.** `derive_identity`
   formats 64 HKDF-derived bytes into 128 hex chars to reach
   `PrivateIdentity::new_from_hex_string`, explicitly to avoid naming the dalek
   types. Retinue takes the bytes: `PrivateIdentity::from_secret_bytes(&[u8; 64])`,
   X25519 secret first, Ed25519 signing seed second. The HKDF stretching stays a
   Mere concern; retinue only needs the byte-level constructor.

Items 2, 3, 4, 6 and 7 are all one design move: **the link is an object, not an
event stream you filter.** That is the single largest divergence from Beechat's
shape and should be settled before R3 rather than during it.

## R0 API surface

Derived from what the probe actually consumes. Illustrative sketch, not
compile-ready: names and signatures are a target for R0 to land on, and the
oracle will move some of them.

```rust
// wire: sans-io, no runtime, no I/O. This is all of R0.
pub struct PrivateIdentity { /* X25519 secret + Ed25519 signing key */ }
impl PrivateIdentity {
    pub fn from_secret_bytes(bytes: &[u8; 64]) -> Result<Self, IdentityError>;
    pub fn public(&self) -> Identity;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity { /* X25519 public + Ed25519 verifying, 64 bytes */ }
impl Identity {
    pub fn public_key_bytes(&self) -> &[u8; 32];   // X25519
    pub fn verifying_key_bytes(&self) -> &[u8; 32]; // Ed25519
    pub fn address_hash(&self, name: &DestinationName) -> AddressHash;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DestinationName { /* app name + dotted aspects */ }
impl DestinationName {
    pub fn new(app: &str, aspects: &str) -> Self;
    pub fn name_hash(&self) -> NameHash; // the 10-byte truncation, the only
                                         // form that matches on the wire
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressHash([u8; 16]);

// Packets: encode/decode is a total function over bytes, which is what makes
// oracle fixtures replayable in CI with no Python and no runtime.
pub struct Packet { /* header, destination, context, payload */ }
impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError>;
    pub fn encode(&self, out: &mut Vec<u8>);
}

// Announces validate on decode; an unvalidated announce is unrepresentable.
pub struct Announce {
    pub identity: Identity,
    pub name_hash: NameHash,
    pub address_hash: AddressHash,
    pub app_data: Vec<u8>,
}
impl Announce {
    /// Verifies the announce signature. Returns `Err` if it does not check out.
    pub fn decode(packet: &Packet) -> Result<Self, WireError>;
    pub fn build(identity: &PrivateIdentity, name: &DestinationName,
                 app_data: Option<&[u8]>) -> Packet;
}

/// Post-framing payload capacity, so callers never guess a chunk size (item 7).
pub const fn max_payload(context: PacketContext) -> usize;
```

The endpoint runtime (`Endpoint`, `Destination`, `Link`, interfaces) is R1 to R4
and sits on top of this in a tokio shell. Sketching it now would be guessing
ahead of the oracle; the one commitment made in advance is that `Link` is an
owned handle with its own I/O, per the note above.

## Next actions

R0 and R1 are done. Next:

1. **Capture a live link handshake.** This unblocks R3 and settles the two live
   unknowns above: whether a link request carries the 3-byte MTU/mode trailer, and
   how the link id is computed (over the full request data, or only the 64 bytes of
   keys). A wrong guess on either means no link ever completes, with no useful
   error. Drive an `RNS.Link` against a retinue destination over the R1 interface
   and record every packet in both directions.
2. **R2, the endpoint behaviour**: announce cadence, the address book, and path
   requests to the degree an endpoint needs them.
3. **R3, links**, against the captured handshake.

The sequencing lesson, now vindicated twice: **capture before coding.** On the
announce ratchet, on the token key split, and on the framing escape rules, the
paper research and the readable Rust implementation agreed with each other, and on
the first two they were both wrong. Only bytes settled it. The framing turned out
fine, but it was checked, not trusted, and that cost about twenty minutes.

## Progress

- **2026-07-06** — repo scaffolded at `repos/retinue`; dual MIT/Apache-2.0;
  crates.io name reserved with a 0.0.1 stub stating scope. No protocol code.
- **2026-07-13** — pinned to RNS 1.3.8 and resolved three of the four open
  questions (version pin, async posture, oracle-in-CI); see Decisions. Audited
  Mere's Beechat probe and derived the R0 API surface from it; see Lessons and
  R0 API surface. Confirmed the Beechat crate is still 0.1.0 (last published
  2025-10-14), so the staleness premise for owning this holds.

- **2026-07-13 (same day) — R0 landed.** Built the oracle harness
  (`oracle/capture.py`, venv pinned to `rns==1.3.8`) and captured 11 fixtures.
  Implemented the wire module: `hash`, `identity`, `destination`, `packet`,
  `announce`, `token`. 20 tests green, 12 of them replaying real RNS bytes.

  The oracle overturned two things that paper research had confidently inferred,
  which is the entire argument for having built it first:

  1. **Announces carry a ratchet, and Beechat cannot parse one.** 32-byte X25519
     key between `rand_hash` and the signature, signalled by header bit 5. Beechat
     models neither, so it reads the ratchet where the signature should be. The
     uncomfortable corollary: **Mere's Reticulum probe has only ever talked to
     other Beechat nodes.** Its wire compatibility with real RNS was never tested,
     and against a ratchet-enabled peer it would simply fail. R5 should be treated
     as a fix, not a swap.
  2. **The token is AES-256 with the signing key first**, and Beechat's
     `Identity::encrypt` hardcodes a 16-byte split that is only right under a
     non-default feature. On a default build its two encryption paths derive
     different keys from the same secret. Settled by decrypting a real RNS token
     against all four (AES size x split order) combinations.

  Also confirmed by known-answer test: RNS, Beechat and retinue all agree that
  `example_utilities.announcesample.fruits` under the fixture identity hashes to
  `2419dca3c93718497b91990373df1503`.

- **2026-07-13 (same day) — R1 landed.** HDLC framing plus a tokio TCP interface.
  Framing captured first, per the R0 lesson (`oracle/capture_tcp.py` records a
  socket that speaks nothing while RNS talks at it): flag `0x7E`, escape `0x7D`,
  XOR `0x20`. The capture handed us the flag-escape case for free, because the
  fixture destination hash happens to contain a literal `0x7E` and RNS stuffed it
  to `7d 5e`. The escape-byte rule was then pinned deliberately, by announcing
  `app_data` of `7e 7d 7e 7d 00 ff` and reading `7d5e 7d5d 7d5e 7d5d 00 ff` off
  the wire: **both** special bytes are escaped.

  **The live gate passes** (`oracle/interop_r1.py`): a real RNS accepted an
  announce retinue built, signed and framed, and retinue validated RNS's announce
  over the same TCP connection. That is genuine two-way wire compatibility with the
  reference implementation, which is more than the Beechat-based probe in mere has
  ever demonstrated.

  29 tests green. Framing tests replay the real captured TCP stream, including
  feeding it back one byte at a time to prove the deframer survives arbitrary TCP
  chunking.
