# The oracle

The Python reference implementation of Reticulum, used as a **black-box interoperability
oracle**: we run it, drive it through its public API, and record the bytes it produces. We
never read its source.

That discipline is not squeamishness. Two reasons:

1. **Licensing.** RNS's post-2025 license carries clauses we are not willing to take on.
   retinue is MIT/Apache-2.0, and the provenance of every byte-level fact in it has to be
   defensible. retinue is derived from the public-domain protocol specification, from the
   MIT-licensed Beechat `reticulum` crate, and from bytes observed on the wire. Nothing
   else.
2. **It keeps us honest.** Reading an implementation invites copying its bugs and its
   accidents. Observing its output forces every question to be answered by what actually
   goes on the wire. This paid for itself immediately: Beechat, the readable Rust
   implementation, turns out to be wrong in two places that only wire observation could
   have caught (see below).

Reading RNS source is therefore forbidden. Running it, calling its documented API,
inspecting its public constants at runtime, and reading its output are all fine.

## Setup

```sh
py -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

`requirements.txt` pins `rns==1.4.0`, which includes the 1.3.9 `rnsh` security update and
is the current PyPI release. Re-pin deliberately, not on every upstream release. The
committed fixture corpus remains labelled 1.3.8 because those files are historical byte
observations; current compatibility is established by the live gates below.

RNS 1.3.9 and 1.4.0 have an observed `TCPClientInterface.ifac_size` initialization race
when a connected peer sends its first frame immediately. The direct-TCP Rust probes wait
250 ms after accept so this matrix measures protocol interoperability instead of RNS
constructor timing. Retinue's production TCP interface has no such delay.

## Capture

```sh
./.venv/Scripts/python.exe -u capture.py
```

`-u` matters. `RNS.exit()` hard-exits the process and will discard buffered stdout, so a
buffered run looks like it silently did nothing.

This writes `../tests/fixtures/`: the announce corpus, the negative (corrupted) announces,
an identity vector, an encrypted token, and `manifest.json` describing each one and the
facts it pins down.

The fixtures are **committed**. `cargo test` replays them and needs no Python, so CI stays
Python-free. The live oracle is a local gate, run when the wire format is in question.

## What the oracle settled

These were unanswerable from the manual and from Beechat, and a wrong guess on any of them
is a silent, total wire incompatibility.

- **Announces carry a ratchet, and Beechat cannot parse one.** A ratchet-enabled
  destination inserts a 32-byte X25519 public key between `rand_hash` and the signature,
  and signals it with **bit 5 of header byte 0** (the Context Flag). Beechat 0.1.0 models
  neither the flag nor the field, so it reads the ratchet where the signature should be and
  fails verification. Ratchets are off by default, which is the only reason a Beechat/RNS
  pairing appears to work at all.
- **The announce signature covers the destination hash, which is not in the payload.** It
  comes from the packet header. The signed message is the wire payload with the destination
  hash prepended and the signature spliced out, so `app_data` sits at a different offset in
  the signed form than on the wire.
- **The token is AES-256 with the signing key first.** `HKDF-SHA256(ikm=x25519_shared,
  salt=identity_hash, info=<empty>, len=64)`, then `sign_key = derived[0..32]`,
  `enc_key = derived[32..64]`. Established by decrypting a real RNS token against all four
  combinations of {AES-128, AES-256} x {sign-first, enc-first}; only one authenticates and
  decrypts. Beechat gets this right on its `PrivateIdentity` path and wrong on its
  `Identity` path, which hardcodes a 16-byte split that is only correct under a non-default
  feature.
- **`NAME_HASH_LENGTH` is 10 bytes**, which appears nowhere in the manual.

## The live interop gate

```sh
./.venv/Scripts/python.exe -u run_live.py
```

This runs all eleven live gates in isolated processes: announce, path resolution, links in
both roles, request/response, endpoint streaming, Resources in both directions (including
the 2.5 MB segmented cases), and transport routing. `interop_r1.py` is the first gate. It
starts retinue (`examples/interop_tcp.rs`), points a real RNS `TCPClientInterface` at it,
and checks **both** directions:

- **retinue -> RNS.** RNS's own announce handler accepts an announce retinue built,
  signed and framed. Reaching the handler at all means it passed RNS's signature
  validation.
- **RNS -> retinue.** retinue de-frames, decodes and validates RNS's announce over the
  same socket.

Either direction failing means we are not wire-compatible, whatever the unit tests say.
This is a **local gate**, not CI: CI replays the committed fixtures instead.

## Files

| file | what |
| --- | --- |
| `requirements.txt` | the current live-oracle pin: `rns==1.4.0` |
| `run_live.py` | the complete eleven-gate mixed-runtime matrix |
| `capture.py` | R0 fixtures: identity vector, announces, negatives, a token |
| `capture_tcp.py` | R1 fixtures: the raw TCP stream, and the framing rules |
| `interop_r1.py` | the R1 live two-way announce gate |
| `capture_link.py` | link handshake probe: the trailer and link-id derivation |
| `link_crypto_probe.py` | pins the link key derivation by decrypting real RNS link traffic |
| `capture_link_session.py` | R3 fixtures: a deterministic captured link session |
| `interop_link.py` | the R3 live encrypted-link gate |
| `.venv/` | gitignored |

The link-crypto probes are worth a note on method. `link_crypto_probe.py` acts as a link
initiator with a *fixed* ephemeral secret against a real RNS responder. Because we know our
own secret and RNS's ephemeral public arrives in the proof, the ECDH shared secret is
computable, so we can derive the session key ourselves and prove it by having RNS decrypt
data we encrypted, and by decrypting RNS's reply. That, plus RNS's own
`Link.link_id_from_lr_packet` / `mode_from_lr_packet` helpers as a cross-check, pinned the
entire link layer before a line of Rust was written.
