# retinue v0 — Endpoint-Scoped Reticulum

**Status (2026-07-13):** **R0, R1, R2, and R3 are done, all verified against the
oracle.** retinue holds an identity; builds and validates announces (ratcheted and
not); frames HDLC; exchanges announces with a real RNS 1.3.8 over live TCP both
ways; learns peers into an address book and emits path requests; is a **full
encrypted-link peer in both roles** (initiate and accept, data both ways, keepalive,
teardown, request/response). 43 tests green, plus five live mixed-runtime interop
gates that pass. Remaining for v0: R4 (resources) and R5 (fix mere onto retinue).
Direction decided in the Mere workspace (mere design_docs,
`2026-06-29_reticulum_transport_plan.md` Direction section and
`2026-07-06_lxmf_key_addressed_mail_research.md`): Mere stewards its own
implementation rather than depending on Beechat's stale 0.1.0 or FreeTAK's
daemon-shaped EPL stack. The Reticulum protocol is public domain; upstream
reference-implementation stewardship is in flux (license change April 2025,
founder stepped back December 2025, community forks).

## Goal

A library crate that lets a host process *be* a Reticulum endpoint,
wire-compatible with RNS 1.3.x: hold an identity, announce it, resolve peers
from announces, establish links, exchange packets and resources. Embedding is
the product; the first consumer is Mere's `transport` crate behind its
`Transport` trait, replacing the Beechat pin without changing the probe's shape
(deterministic identity from a seed, announce-bound peer ids, ALPN-to-destination
mapping, bilateral streams).

## Non-goals

- **Routing.** No transport-node behavior; a retinue accompanies one peer.
- **LXMF.** Message-layer protocols sit above this crate (a possible later
  `lxmf-wire`-shaped sibling, only if Reticulum-world interop is wanted).
- **Daemon.** No standalone process, no RPC surface; library embed only.
- **Every interface type.** TCP first; serial/RNode/LoRa later; BLE out of
  scope for v0.

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
- **R4 — resources.** The resource transfer mechanism over links (segmented
  large payloads, progress, cancellation).
  Done when: a multi-megabyte resource round-trips retinue ↔ oracle intact in
  both directions.
- **R5 — Mere adoption.** Implement Mere's `Transport` trait on retinue;
  replace the Beechat pin behind the existing feature gate; carry over the
  probe's tests (deterministic seed → destination, announce-bound `PeerID`,
  ALPN mapping, loopback streams).
  Done when: Mere's reticulum-lane tests pass on retinue with the Beechat
  dependency deleted from the tree.
- **Later, unscheduled:** serial/RNode interface, an `lxmf`-wire sibling for
  Reticulum-world mail interop, routing (probably never).

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
