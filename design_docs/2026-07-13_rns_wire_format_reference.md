# RNS 1.x wire format reference (retinue's ground truth)

**Status (2026-07-13, amended):** first consolidated wire reference. Pinned to **RNS 1.3.8**.
Assembled from the public-domain Reticulum manual and the MIT Beechat crate
(`reticulum-0.1.0`), then adversarially reviewed.

**Amendment: the oracle now exists, and R0 is settled against it.** `oracle/capture.py`
drives RNS 1.3.8 as a black box and writes `tests/fixtures/`. The R0 surface (identity,
hashing, destination naming, the packet header, announces, and the identity token) is no
longer inference: retinue's announces are byte-identical to RNS's from the same inputs,
and retinue decrypts tokens RNS encrypted to it. See **section 0** below for the facts the
oracle settled, several of which **contradict what this document originally inferred**.

Everything from links (R3) onward is still document-and-Beechat sourced, so the caution
below still applies to those sections. Section 4's open questions are answered where
section 0 says so, and stand where it does not.

---

## 0. What the oracle settled (2026-07-13)

These are `[O]` facts: observed from bytes RNS actually emitted, or from independent
recomputation against them. They outrank every `[M]`, `[B]`, `[X]` and `[I]` claim below.

**Ratchets are carried in the announce, and the Context Flag signals them.** A
ratchet-enabled destination inserts a 32-byte X25519 public key **between `rand_hash` and
the signature** (payload offsets 84..116, pushing the signature to 116..180), and sets
**bit 5 of header byte 0**. Observed: an identical destination announces at 148 payload
bytes with flags `0x01`, and at 180 bytes with flags `0x21`, the first 74 bytes
byte-identical. The ratchet **is** covered by the signature. `ratchet_id =
trunc10(SHA256(ratchet_public_key))`, confirmed by recomputation.

> Consequence: **Beechat 0.1.0 cannot parse or validate a ratcheted announce.** It models
> neither the flag nor the field, so it reads the ratchet where the signature belongs.
> Ratchets are off by default, which is the only reason a Beechat/RNS pairing appears to
> work. Any Reticulum stack built on Beechat is one `enable_ratchets()` away from silent
> total failure against its peer.

**The announce signed message is not the announce payload.** The Ed25519 signature covers:

```text
dest_hash(16) || x25519_pub(32) || ed25519_pub(32) || name_hash(10) || rand_hash(10)
              || [ratchet(32)]  || app_data(*)
```

That is the wire payload with the **destination hash prepended** (it is not in the payload
at all: it comes from the packet header) and the **signature spliced out** (which moves
`app_data`). Established by verifying all four candidate constructions against all four
announce variants: only this one verifies in every case, and the variant without the
destination hash fails in every case. Corroborated by a negative fixture in which a byte
flipped in the *header* breaks the signature.

**The token is AES-256 with the signing key first.**

```text
derived  = HKDF-SHA256(ikm = x25519_shared, salt = identity_hash(16), info = <empty>, len = 64)
sign_key = derived[0..32]      enc_key = derived[32..64]
token    = ephemeral_x25519_pub(32) || IV(16) || AES-256-CBC/PKCS7 || HMAC-SHA256(32)
```

The HMAC covers **`IV || ciphertext` only**; the ephemeral public key is *not*
authenticated. Established by decrypting a real RNS token against all four combinations of
{AES-128, AES-256} x {sign-first, enc-first}: exactly one both authenticates and decrypts.
The HKDF salt was obtained by *calling* `Identity.get_salt()`, which returns the identity
hash, and the info string by calling `get_context()`, which returns `None`.

> Consequence: Beechat gets this right on its `PrivateIdentity` path (`split at
> DERIVED_KEY_LENGTH/2`) and **wrong on its `Identity` path**, which hardcodes `[..16]` /
> `[16..]` — correct only under the non-default `fernet-aes128` feature. On a default build
> those two paths derive different keys from the same secret.

**The header flag byte** is `ifac(7) | header_type(6) | context_flag(5) | propagation(4) |
destination_type(3..2) | packet_type(1..0)`. Confirmed by the `0x01` → `0x21` transition
(only bit 5 moves) and by `HEADER_MINSIZE = 19` = 2 + 16 + 1.

**`NAME_HASH_LENGTH` is 10 bytes**, read off `RNS.Identity.NAME_HASH_LENGTH = 80` bits.
This appears nowhere in the manual; the reviewers correctly flagged it as crate-only, and
it is now confirmed.

**Known-answer vector.** Private key
`f0ecbba4...6d6c` (repeated, x25519 secret then ed25519 seed) yields identity hash
`70de4e01d8064fae79daa0e198233f56`, and destination
`example_utilities.announcesample.fruits` hashes to `2419dca3c93718497b91990373df1503` —
the same value the Beechat crate's own test prints. RNS, Beechat, and retinue now agree.

**TCP framing is HDLC** (`oracle/capture_tcp.py`): flag `0x7E`, escape `0x7D`, escaped byte
XORed with `0x20`, and **both** special bytes are escaped. The flag case appeared
unprompted, because the fixture destination hash contains a literal `0x7E` and RNS stuffed
it to `7d 5e`. The escape-byte case was pinned deliberately, by announcing `app_data` of
`7e 7d 7e 7d 00 ff` and reading `7d5e 7d5d 7d5e 7d5d 00 ff` off the wire.

### 0.1 Links (`oracle/capture_link.py`, 2026-07-13)

Captured by provoking a handshake in both directions without implementing links: retinue
announces so RNS links *to* it (showing the request), and retinue fires a raw link request
*at* RNS so RNS proves back (showing the proof, addressed to the link id).

**A link request is 67 bytes, not 64. A link proof is 99, not 96.** Both carry a 3-byte
trailer after the key material:

```text
bits 23..21   AES mode  (0 = AES-128-CBC, 1 = AES-256-CBC)
bits 20..0    MTU
```

Observed: the initiator sends `20 20 00` = mode 1 (AES-256), MTU 8192. The responder
answers `20 01 f4` = mode 1, MTU **500**, which is exactly `Reticulum.MTU`. So this is an
**MTU negotiation**, and the link cipher is AES-256 on both ends. Beechat sends a bare
64-byte request and does not participate in any of it.

**The link id** is a truncated hash over the request, and none of the obvious guesses is
right:

```text
link_id = trunc16(SHA256( (flags & 0x0F) || destination(16) || context(1) || payload[..64] ))
```

`hops` is excluded, which is sensible since it mutates in transit. The payload is
**truncated to the 64 bytes of keys**, so the negotiable trailer deliberately does not
affect the id. Solved against two independently captured (request, link id) pairs; only
this formula satisfies both, and the 67-byte pair is what proves the truncation.

> **Honest caveat.** Both captured samples had `flags == 0x02`, where `& 0x0F` is a no-op.
> The capture therefore does **not** prove the mask; it is taken on [M]'s and [B]'s
> authority. It only becomes observable for a link request arriving over a transport hop
> (header type 2, or propagation = transport). If a multi-hop link ever fails to establish,
> look here first.

Encoded in `src/link.rs`, with both captured vectors as regression tests. Section 4's
questions **O-4b** and **O-4c** (the proof's field order and length) are partially answered:
the length is 99, and the trailer is last. Whether the first 64 bytes are the signature or
the 32-byte key comes first is still open, and needs the signed pre-image to settle.

### 0.2 Resources (`oracle/capture_resource.py`, 2026-07-13) — protocol reversed, not yet implemented

A resource is RNS's segmented transfer of a payload too large for one packet, over a link.
Captured by having RNS send retinue a 4 KB resource; retinue dumped every decrypted link
packet. The flow, by link context byte:

```text
0x02 RESOURCE_ADV   advertisement (msgpack map; retransmitted until the receiver responds)
0x03 RESOURCE_REQ   receiver requests parts it still needs
0x01 RESOURCE       a part (segment) of the payload
0x04 RESOURCE_HMU   hashmap update, for resources with more parts than one advert carries
0x05 RESOURCE_PRF   receiver's proof of receipt
0x06 RESOURCE_ICL   sender cancels (seen when retinue never responded: status FAILED)
0x07 RESOURCE_RCL   receiver cancels
```

The **advertisement** is a msgpack map (decoded from a real capture):

| key | meaning | example |
| --- | --- | --- |
| `t` | transfer size, after compression | 720 |
| `d` | uncompressed data size | 4096 |
| `n` | number of parts | 2 |
| `h` | resource hash (32) | `11b44f89...b60e` |
| `o` | original (uncompressed) hash (32) | `11b44f89...b60e` |
| `r` | random hash (4) | `fddb2d74` |
| `f` | flags | 3 |
| `m` | hashmap: 4 bytes per part | `202ecd18fe3e1fcb` (2 parts) |
| `i`, `l`, `q` | opaque (interleave / segment / request), not yet named | 1, 1, nil |

`t = 720 < d = 4096` means RNS **bz2-compressed** the payload before segmenting, then split
it into `n` parts each keyed by a 4-byte map hash. The receiver must request parts, collect
them, decompress, verify against `o`, and prove.

This is a windowed, stateful protocol with compression, and it is **not yet implemented**. It
is also not on the path to R5 (mere uses bilateral link streams, not resources). Tooling:
`oracle/capture_resource.py` and `examples/resource_probe.rs` reproduce the capture.

---

---

## 1. Status and provenance

### 1.1 What this is

The single reference retinue's `wire` module is implemented against. It supersedes ad-hoc
notes. Where it is wrong, the fix goes here first and into code second.

### 1.2 License discipline (unchanged from the v0 plan, sections "Reference discipline")

- **Public-domain protocol spec and manual** (`reticulum.network/manual`, 1.3.x snapshot).
  Cited below as **[M]**. Authoritative on intent, constants, and the header layout.
- **Beechat `reticulum-0.1.0` (MIT)**, read freely. Cited as **[B]** with `file:line`.
  It is a *working* implementation and the only byte-level source we have, but it is
  **0.1.0, stale, and a generation behind on the header**. It has zero ratchet code and
  implements 4 of the 21 packet contexts it declares.
- **The Python reference implementation was never read.** It is a black-box oracle only:
  run, driven, and observed. Cited as **[O]** where an answer is expected from it. There
  are no [O] facts in this document yet.
- **Independent recomputation** by me, from allowed sources, with `hashlib` +
  `cryptography`. Cited as **[X]**.
- **Inference** by me on top of the above. Cited as **[I]**. An [I] claim is a hypothesis,
  not a fact, and is never a basis for shipping without a fixture.

### 1.3 Confidence posture

Three review passes materially changed the picture. The corrections that matter most:

1. **The Beechat header is wrong and the manual settles it.** Bit 5 is a **context flag**;
   propagation type is a **single bit** at bit 4. Beechat models bits 5-4 as a 2-bit
   propagation field, so it *misparses on receive* any packet with the context flag set.
   This is not an oracle question. It is a crate bug, resolved by an allowed source.
2. **The link ID preimage is crate-only, and the manual arguably contradicts it.** The
   manual says "the link id is a hash of the entire link request packet." Beechat hashes
   a masked header byte, the destination, the context byte, and only the **first 64 bytes**
   of the payload. Those are not the same construction.
3. **The announce signed-message byte order rests on Beechat alone.** The manual's prose
   list of announce contents puts app_data *before* the random blob, which is the opposite
   of Beechat's order, and names one public key where there are two. The manual corroborates
   set membership only, not order.
4. **IFAC derivation is documented and was previously reported as unknowable.** [M]: an
   interface with a network name or passphrase derives a shared Ed25519 signing identity and
   signs the **entire packet**; the (possibly truncated) signature is the access code.
5. **Ratchets are documented as a per-destination, link-less feature.** [M]: "Asymmetric,
   link-less packet communication can also provide forward secrecy, with automatic key
   ratcheting, by enabling ratchets on a per-destination basis." That is evidence links do
   **not** ratchet (they already have forward secrecy from the ephemeral handshake). It does
   not tell us anything about the announce bytes.
6. **`Identity::encrypt` in Beechat is dead, non-functional code.** It splits the derived
   key 16/48 and panics on the default AES-256 path. Consequently the 80-byte
   single-destination crypto overhead used to "confirm" `ENCRYPTED_MDU` is inferred from
   the *shape* of code that cannot execute. The MDU arithmetic below is a consistency check,
   not a confirmation.

---

## 2. Constants

An error in this table is a silent wire-incompatibility bug. Source column: **[M]** manual,
**[B]** Beechat crate, **[X]** recomputed by me, **[I]** inferred.

### 2.1 Hashing and keys

| Constant | Value | Source |
|---|---|---|
| Hash function | SHA-256, everywhere | [M] primitives list; [B] `hash.rs:12` |
| Full hash | 32 bytes | [B] `hash.rs:12` |
| Address hash (`TRUNCATED_HASHLENGTH`) | **16 bytes** (128 bits), non-configurable | [M] reference.html; [B] `hash.rs:13` |
| Truncation method | plain prefix of the digest | [B] `hash.rs:15-19` |
| Name hash | **10 bytes** | [B] `destination.rs:59` **only. Not in the manual.** |
| Announce random hash | **10 bytes** | [B] `destination.rs:60` **only. Not in the manual.** |
| X25519 public key | 32 bytes | [B] `identity.rs:15` |
| Ed25519 verifying key | 32 bytes | [B] `identity.rs:15` |
| Public identity blob (`KEYSIZE`) | **64 bytes = X25519 pub ‖ Ed25519 verifying**, X25519 first | [B] `identity.rs:89-124`; [M] KEYSIZE = 512 bits = "256 bit encryption key, 256 bit signing key" |
| Private identity blob | **64 bytes = X25519 secret ‖ Ed25519 signing SEED**, X25519 first | [B] `identity.rs:270-291, 309-321` |
| Ed25519 signature | 64 bytes | [B] `destination.rs:4` |
| `RATCHETSIZE` | 256 bits = 32-byte X25519 public key | [M] reference.html |
| `RATCHET_COUNT` (retained) | 512 | [M] reference.html |
| `RATCHET_INTERVAL` | 1800 s | [M] reference.html |
| Received-ratchet expiry | 30 days | [M] reference.html |

Truncation lengths **exercised anywhere in Beechat** are 16 and 10, and nothing else. That
is not a statement about the whole protocol: the HMAC tag is a full, untruncated 32 bytes
(`fernet.rs:28`), and RNS 1.x has resources, ratchets and announce caching that Beechat does
not model at all.

### 2.2 Framing sizes

| Constant | Value | Source |
|---|---|---|
| `Reticulum.MTU` | **500 bytes** | [M] reference.html |
| `Packet.PLAIN_MDU` | **464 bytes** | [M] reference.html |
| `Packet.ENCRYPTED_MDU` | **383 bytes** | [M] reference.html |
| DATA field range | 0 to 465 bytes | [M] understanding.html |
| IFAC field | 1 to 64 bytes when present; **length is not on the wire** | [M] understanding.html, interfaces.html (`ifac_size` 8-512 bits) |
| Type-1 header overhead | **19 bytes** = 2 + 16 + 1 | [I] name, value forced; corroborated four ways by [M]'s size table |
| Type-2 header overhead | **35 bytes** = 2 + 32 + 1 | [I] name, value forced (35 + 465 = 500) |
| `PATHFINDER_M` (max hops) | 128 | [M] reference.html; [B] `transport.rs:45` |

`PLAIN_MDU` and the "0-465" DATA range do **not** contradict each other: 465 = 500 - 2 - 32 - 1
(raw ceiling, two addresses, no IFAC), and 464 = 465 - 1 (one byte reserved for the minimum
IFAC field). The names `HEADER_MINSIZE`, `HEADER_MAXSIZE` and `IFAC_MIN_SIZE` are **retinue's
coinages**; no allowed source uses them.

**Do not copy from Beechat:** `PACKET_MDU = 2048` (`packet.rs:9`) is an internal buffer size,
and `Interface::mtu() = 2048` (`tcp_client.rs:213` and friends) is dead code, never called
anywhere in the crate. Neither is a protocol constant. This is Lesson 7 of the v0 plan.

### 2.3 Packet sizes from the manual's size table

Every row is [M] understanding.html. The "= 19 + n" column is [X] arithmetic, and it is our
strongest cross-check on the 19-byte type-1 header.

| Packet | Size | = 19 + data | Beechat agrees? |
|---|---|---|---|
| Link keepalive | 20 | 19 + 1 | yes |
| Path request | 51 | 19 + 32 | (not built by the crate) |
| Link request | 83 | 19 + 64 | yes |
| Link RTT | 99 | 19 + 80 | **NO. The crate's construction yields 83** |
| Link proof | 115 | 19 + 96 | yes |
| Announce | 167 | 19 + 148 | yes |
| Link establishment total | 297 / 3 packets | 83 + 115 + 99 | consistent |

The RTT row is the one that does not reconcile. See section 3.4.7.

### 2.4 Token (symmetric crypto)

| Constant | Value | Source |
|---|---|---|
| Cipher | AES-256-CBC, PKCS7 padding | [M] understanding.html; [B] `fernet.rs:17-24` |
| MAC | HMAC-SHA256, **32-byte tag, untruncated** | [B] `fernet.rs:28, 147-150` |
| IV | 16 bytes, random, first in the token | [B] `fernet.rs:30, 130-131` |
| `FERNET_OVERHEAD_SIZE` | **48 bytes** (IV 16 + HMAC 32) + 1..16 PKCS7 | [B] `fernet.rs:31` |
| Fernet divergences | no version byte, no timestamp, no base64 | [B] `fernet.rs:37-43`; [M] "No Fernet version and timestamp metadata fields" |
| `DERIVED_KEY_LENGTH` | 64 bytes (AES-256 path, the default) | [B] `identity.rs:17-21`, `Cargo.toml:41-44` |
| KDF | HKDF-SHA256, **info = empty**, L = 64 | [B] `identity.rs:404-410` |
| HKDF salt (link) | the 16-byte link ID | [B] `link.rs:422-424` |
| Key split | `derived[0..32]` = HMAC key, `derived[32..64]` = AES-256 key | [B] `identity.rs:356-360`; order confirmed by `fernet.rs:92` (`new_from_slices(sign_key, enc_key, rng)`) |

### 2.5 Link lifecycle (manual is authoritative; Beechat's timers are its own product choices)

| Constant | Value | Source |
|---|---|---|
| `Link.CURVE` | Curve25519 | [M] |
| `Link.KEEPALIVE` | 360 s | [M] (Beechat uses 5 s, `transport.rs:51`) |
| `Link.STALE_TIME` | 720 s | [M] (Beechat reaps at 20 s, `transport.rs:48`) |
| `Link.STALE_GRACE` | 5 s | [M] |
| `Link.KEEPALIVE_TIMEOUT_FACTOR` | 4 | [M] |
| `Link.ESTABLISHMENT_TIMEOUT_PER_HOP` | 6 s | [M] |
| `Reticulum.LINK_MTU_DISCOVERY` | True | [M] reference.html |
| `LINK_MTU_SIZE` | 3 bytes | [B] `link.rs:23` (never emitted by the crate) |

### 2.6 TCP framing

| Constant | Value | Source |
|---|---|---|
| Frame flag | `0x7E` | [B] `iface/hdlc.rs:3` |
| Escape byte | `0x7D` | [B] `iface/hdlc.rs:4` |
| Escape mask | `0x20` (XOR) | [B] `iface/hdlc.rs:5` |
| Escaped `0x7E` | `7D 5E` | [B] `hdlc.rs:15-16` |
| Escaped `0x7D` | `7D 5D` | [B] `hdlc.rs:15-16` |
| FCS / CRC / length prefix | **none** | [B] `hdlc.rs` in full (97 lines) |

### 2.7 Known-answer vectors

All recomputed independently by me with `hashlib` + `cryptography` [X]. They confirm the
**crate's algorithm**, not RNS's. Oracle test #1 is to confirm the destination hash.

```
seed (used for BOTH halves; the halves are independent in general)
  f0ecbba49e783dee14ffc6c9f1e1251efa7d7629e0fa32413c5c59ec2e0f6d6c

x25519 public   a8fd56cbca13577c24914cc4c13308b7d7f3e20bd39c55a4e636984655be3438
ed25519 public  84f6da8c37b5f343568b185a20c63b5bf011a3d60ee805bb9e151371ea1d5555
identity_hash   70de4e01d8064fae79daa0e198233f56

app_name        "example_utilities"
aspects         "announcesample.fruits"
expanded name   "example_utilities.announcesample.fruits"   (39 bytes, not 38)
name_hash       6f233dfd9aa4cbd4a1e2
dest_hash       2419dca3c93718497b91990373df1503

announce with random_hash = 00112233445566778899, no app_data:
signed message (100 B) = dest_hash ‖ x25519 ‖ ed25519 ‖ name_hash ‖ random_hash
signature       4596d1161e8856dda74789e9c7d121c49f52fee2fc87a336178d5ff887c01363
                0903275dd494ee90df6fafd145c8e2c1e4e7ee809fde52ff7292f4c3cc42fc07
full packet (167 B):
  01 00 2419dca3c93718497b91990373df1503 00
  a8fd..3438 84f6..5555 6f233dfd9aa4cbd4a1e2 00112233445566778899 4596..fc07
```

Path-request name, for the Plain-destination question:

```
expanded name   "rnstransport.path.request"
sha256 (full)   7926bbe7dd7f9aba88b061551600a25d06ef0f7578202730bd2f224200715efe
name_hash       7926bbe7dd7f9aba88b0
IF Plain destinations hash SHA256(name_hash)[0..16]:
  dest_hash     6b9f66014d9853faab220fba47d02761      <- [I], see 3.1.5
```

---

## 3. The wire format, area by area

### 3.1 Identity and hashing

#### 3.1.1 Identity blobs: VERIFIED [B], three independent sites agree

```
Public identity, 64 bytes
 off  len  field
   0   32  X25519 public key      (Montgomery-u, little-endian)
  32   32  Ed25519 verifying key  (compressed Edwards)

Private identity, 64 bytes
 off  len  field
   0   32  X25519 secret scalar   (stored raw; clamped at DH time)
  32   32  Ed25519 signing SEED   (not the expanded 64-byte secret)
```

X25519 first in both. [B] `identity.rs:89-124` (public parse/emit), `identity.rs:270-291,
309-321` (private parse/emit), `destination.rs:128-141, 249-257` (announce, both directions).
The two halves need not be related; Beechat's own test uses the same 32 bytes for both.

This confirms the v0 plan's `PrivateIdentity::from_secret_bytes(&[u8; 64])`, "X25519 secret
first, Ed25519 signing seed second" (plan line 164; the signature itself is at line 181).

#### 3.1.2 Identity hash: VERIFIED [B] [X]

```
identity_hash = SHA256( x25519_pub[32] ‖ ed25519_pub[32] )[0..16]
```
[B] `identity.rs:56-64` + `hash.rs:86-90`. This is the **only** place raw public-key bytes
are hashed. Everywhere downstream the identity participates as this 16-byte digest.

#### 3.1.3 Name hash: VERIFIED [B] [X], but the length is crate-only

```
expanded_name = app_name ‖ "." ‖ aspects        (UTF-8, no length prefix, no NUL)
name_hash     = SHA256(expanded_name)[0..10]
```
[B] `destination.rs:70-81, 92-94`. The separator write is **unconditional**: with an empty
aspects string the crate hashes `"app_name."`, trailing dot included. Whether RNS omits the
dot with zero aspects is unknown (O-19). Do not state a "no trailing separator" rule as
verified.

`NAME_HASH_LENGTH = 10` does not appear anywhere in the manual. It is crate-only and it
reproduces the crate's own vectors. Oracle test #1 confirms it.

**The identity is NOT part of the hashed name string.** [M]'s prose says "for single
destinations, Reticulum will automatically append the associated public key as a destination
aspect before hashing," and the crate does no such thing: it hashes only `app_name ‖ "." ‖
aspects` and mixes the identity in afterwards as 16 raw bytes. These two statements conflict.
The crate's construction is self-consistent and reproduces its own KATs; the manual's sentence
is either loose phrasing about a human-readable display name or a real divergence. **Do not
assert what RNS's internal `expand_name` does. We have not read it.** Settled by O-2.

#### 3.1.4 Destination hash (Single): VERIFIED [B] [X]

```
dest_hash = SHA256( name_hash[10] ‖ identity_hash[16] )[0..16]
```
26-byte preimage. No separator, no length prefix, no domain-separation tag.
[B] `destination.rs:348-356`.

```
 0                    10                                26
 +--------------------+---------------------------------+
 | name_hash (10 B)   | identity_hash (16 B)            |
 +--------------------+---------------------------------+
   SHA-256  ->  first 16 bytes  ->  destination address hash
```

#### 3.1.5 Destination hash (Plain / empty identity): INFERRED [I]

`EmptyIdentity::as_address_hash_slice()` returns an empty slice ([B] `identity.rs:195-199`),
so the same `create_address_hash` gives `SHA256(name_hash[10])[0..16]` with a 10-byte
preimage. **But the crate never constructs a Plain destination.** Its `create_path_request_hash`
test ([B] `destination.rs:390-399`) prints the *full 32-byte* SHA-256 of the name, not a
16-byte destination hash, and never calls `create_address_hash`. So both the truncation step
and the premise that RNS's path-request destination is Plain are inferences. Confirm the real
`rnstransport.path.request` destination hash against the oracle (O-15).

**Group destinations** have a type marker and no constructor in the crate. Derivation unknown.

#### 3.1.6 Beechat identity bugs retinue must not inherit

- `Identity::new_from_slices` ([B] `identity.rs:73-87`) calls
  `VerifyingKey::from_bytes(..).unwrap_or_default()`: a malformed Ed25519 point is **silently
  replaced with a default key**, and the identity hash is then computed over the substitute.
  It is on the live link-proof path (`link.rs:498-501`). **Retinue rejects; never defaults.**
  (The announce path does it correctly, `destination.rs:140`.)
- `create_hash` ([B] `hash.rs:15-19`) panics if the output slice exceeds 32 bytes.
- `Identity::encrypt` ([B] `identity.rs:167-190`) is dead and non-functional: it splits the
  derived key `[..16]`/`[16..]` (16/48 under the default AES-256 build), which panics inside
  `Fernet::new_from_slices` on a `copy_from_slice` length mismatch (`fernet.rs:96-97`), and it
  pairs a wire ephemeral public key with a key derived from a *different* ephemeral secret.
  Nothing calls it. **Do not read the single-destination encryption path off this code.**
- `PacketContext::from` ([B] `packet.rs:129-153`) maps every unknown context byte to `None`
  (0x00). Lossy on re-serialization, and it would silently erase any new 1.x context.
- `PrivateIdentity::new_from_name` ([B] `identity.rs:260-268`) derives
  `x25519_secret = SHA256(name)`, `ed25519_seed = SHA256(SHA256(name))`. A useful second KAT
  source, and a demonstration that the two halves are independent.

### 3.2 Packet format

#### 3.2.1 Frame: VERIFIED [M]

```
[HEADER 2 B] [IFAC 1-64 B, only if bit 7 set] [ADDRESSES 16 or 32 B] [CONTEXT 1 B] [DATA 0-465 B]
```

Type-1 (one address), no IFAC:

| Off | Len | Field |
|---|---|---|
| 0 | 1 | header meta byte |
| 1 | 1 | hops (plain u8) |
| 2 | 16 | destination address hash |
| 18 | 1 | context |
| 19 | .. | data |

Type-2 (two addresses), no IFAC:

| Off | Len | Field |
|---|---|---|
| 0 | 1 | header meta byte |
| 1 | 1 | hops |
| 2 | 16 | **transport** address hash |
| 18 | 16 | **destination** address hash |
| 34 | 1 | context |
| 35 | .. | data |

Address order (transport first, destination second) is [B] `serde.rs:33-39, 75-81`. [M]'s
diagram is neutral (`[HASH1][HASH2]`). It is corroborated internally by the packet hash, which
covers only the *destination* and would otherwise not be stable across hops. Still: a swapped
order silently yields garbage destinations on every forwarded packet. Open question O-9.

**Every offset shifts by N when the IFAC flag is set.** Beechat never parses IFAC at all
([B] `serde.rs:85-92` hardcodes `ifac: None` and ignores bit 7), so it misparses every
IFAC-flagged packet. See 3.2.5.

#### 3.2.2 Header byte 0: VERIFIED [M]. The crate is wrong here.

| Bit | Width | Field | Values |
|---|---|---|---|
| 7 | 1 | IFAC flag | 0 open, 1 authenticated |
| 6 | 1 | Header type | 0 = type 1 (one address), 1 = type 2 (two addresses) |
| 5 | 1 | **Context flag** | 0 unset, 1 set |
| 4 | 1 | Propagation type | 0 broadcast, 1 transport |
| 3-2 | 2 | Destination type | 00 single, 01 group, 10 plain, 11 link |
| 1-0 | 2 | Packet type | 00 data, 01 announce, 10 link request, 11 proof |

[M] understanding.html gives all six fields with these widths, and [M] says of the context
flag only that it "is used for various types of signalling, depending on packet context."

Beechat ([B] `packet.rs:181-199`) has **no context flag**: it packs a 2-bit `PropagationType`
at bits 5-4 (`Broadcast=0b00, Transport=0b01, Reserved1=0b10, Reserved2=0b11`). Emission is
accidentally byte-identical for the two values it ever sends. **Decode is not:**
`PropagationType::from(meta >> 4)` folds a set context flag into the propagation field, so a
context-flagged packet is decoded as `Reserved1`/`Reserved2` and the flag is lost.

**Retinue models bit 5 as its own `context_flag: bool`.** What sets it, and what extra wire
bytes it implies, is open question O-3.

Worked meta bytes ([B], all confirmed against the constructors):

| Packet | Meta | Why |
|---|---|---|
| Announce (type 1, broadcast, single) | `0x01` | `destination.rs:279-286` |
| Link request | `0x02` | `link.rs:196-200` (dest type Single, packet type LinkRequest) |
| Link proof | `0x03` | `link.rs:236-239` (dest type Single, packet type Proof) |
| Link data / keepalive / RTT | `0x0C` | `link.rs:335-339` (dest type Link, packet type Data) |
| Manual example, type-2 transport data | `0x50` | [M] |

#### 3.2.3 Hops: byte 1, plain u8

Max 128 (`PATHFINDER_M`) [M] [B]. **Who increments it, and when, is not established.**
Beechat's `create_retransmit_packet` (`transport.rs:610-626`, which does `hops + 1`) is
**dead code with no callers**. The crate's only live repeat path (`transport.rs:667-670`)
re-broadcasts the received packet **verbatim**, hops untouched. Open question O-10.

The hops byte is excluded from the packet hash, which is what makes the hash stable across
the network.

#### 3.2.4 Context byte: a full u8, VERIFIED as constants [B] `packet.rs:104-127`

| Val | Name | Val | Name |
|---|---|---|---|
| 0x00 | None (generic data) | 0x0B | PathResponse |
| 0x01 | Resource (part) | 0x0C | Command |
| 0x02 | ResourceAdvertisement | 0x0D | CommandStatus |
| 0x03 | ResourceRequest (part request) | 0x0E | Channel |
| 0x04 | ResourceHashUpdate | 0xFA | KeepAlive |
| 0x05 | ResourceProof | 0xFB | LinkIdentify |
| 0x06 | ResourceInitiatorCancel | 0xFC | LinkClose |
| 0x07 | ResourceReceiverCancel | 0xFD | LinkProof |
| 0x08 | CacheRequest | 0xFE | LinkRTT |
| 0x09 | Request | 0xFF | LinkRequestProof |
| 0x0A | Response | | |

`0x0F..0xF9` unassigned in the crate. The manual does not enumerate context values, so this
table is **crate-only** and may be missing 1.x additions; enumerate empirically by exercising
each oracle feature and logging the context byte. Beechat *implements* only 0x00, 0xFA, 0xFE,
0xFF.

**Retinue keeps the raw byte** (`Context(u8)`, or an `Unknown(u8)` variant). Normalizing an
unknown context to 0x00, as the crate does, changes the packet hash and destroys forward
compatibility.

#### 3.2.5 IFAC: VERIFIED [M], and it is not the black box previously reported

[M] understanding.html, "Interface Access Codes": an interface with a named virtual network or
passphrase "will derive a shared Ed25519 signing identity, and for every outbound packet
generate a signature of the entire packet. This signature is then inserted into the packet as
an Interface Access Code before transmission. Depending on the speed and capabilities of the
interface, the IFAC can be the full 512-bit Ed25519 signature, or a truncated version." On
receipt the interface checks the signature and drops the packet on mismatch. 512 bits = 64
bytes, which is why `PACKET_IFAC_MAX_LENGTH = 64` ([B] `packet.rs:10`).

What remains unknown: the exact key derivation from name + passphrase, and the exact byte
range signed (is bit 7 set or clear during signing? are the IFAC bytes present-and-zeroed or
absent?). O-23.

**The IFAC length is not on the wire.** A receiver with no IFAC configuration cannot parse an
IFAC-flagged packet at all. The only correct behavior is: **check bit 7 on decode; if set and
we have no IFAC config, drop the packet with a distinct error.** Never misparse it. Retinue
never sets bit 7 (v0 has no IFAC lane).

#### 3.2.6 Packet hash: VERIFIED [B] `packet.rs:250-262`

```
packet_hash = SHA256( (meta & 0x0F) ‖ destination[16] ‖ context[1] ‖ data[..] )   // 32 bytes
```

The mask keeps only destination type and packet type. Excluded: hops, the transport address,
the IFAC flag, the header type, the context flag, the propagation type. That is exactly what
makes it usable as a dedup key across interfaces and hop counts.

Beechat does **no dedup**: `PacketCache::update` is called only from `TransportHandler::send`
([B] `transport.rs:397-399`), its `is_new_packet` return is discarded, and nothing on the
receive path consults it. Its 4-second retention window ([B] `transport.rs:721`) is far too
short to be a replay defence in any case. Retinue sizes its own window from the announce
interval.

#### 3.2.7 Encode hazards

- A packet with `header_type: Type2` and `transport: None` serializes to a 19-byte frame that
  every peer misparses ([B] `serde.rs:33-37` nests the transport write inside an
  `if let Some`). **Retinue makes this unrepresentable:** one enum carrying either one or two
  addresses, not two independent fields.
- [B] `serde.rs:94` reads "all remaining bytes" into a fixed 2048-byte buffer with no bound
  check (`buffer.rs:100-103`), so an oversized frame **panics**. Retinue bound-checks on decode
  and rejects over-MDU packets as a wire error.

### 3.3 Announce

#### 3.3.1 Packet: VERIFIED [B] [M] (the 167-byte total reconciles exactly)

```
type 1, no IFAC
 off  len  field
   0    1  meta = 0x01
   1    1  hops = 0x00 at origin
   2   16  destination address hash
  18    1  context = 0x00
  19  148  announce body (fixed part)
 167    n  app_data
```

2 + 16 + 1 + 148 = 167 = [M]'s stated announce size. This arithmetic identity is the strongest
cross-source confirmation available: it proves the destination hash appears **only** in the
address field and is not repeated in the body.

On a transport-forwarded (type-2) announce every offset from 2 onward shifts by 16, and the
signature covers the **second** address. Reading "the first 16 bytes after the header" is
correct for type 1 only.

#### 3.3.2 Body: VERIFIED [B] `destination.rs:126-151` (parse), `265-276` (emit)

| Off (in DATA) | Len | Field |
|---|---|---|
| 0 | 32 | X25519 public key |
| 32 | 32 | Ed25519 verifying key |
| 64 | 10 | name hash |
| 74 | 10 | random hash |
| 84 | 64 | Ed25519 signature |
| 148 | n | app_data (opaque, unframed, unlengthed) |

`MIN_ANNOUNCE_DATA_LENGTH = 148` ([B] `destination.rs:61-62`). The app_data boundary is fixed
at offset 148: everything past it is app_data.

#### 3.3.3 The signed message: VERIFIED [B] on both paths, NOT corroborated by [M]

```
signed = destination_hash[16]   <- from the packet ADDRESS field; not in the body
       ‖ x25519_pub[32]
       ‖ ed25519_pub[32]
       ‖ name_hash[10]
       ‖ random_hash[10]
       ‖ app_data[n]
length = 100 + len(app_data)
```

[B] `destination.rs:252-263` (sign; note the buffer `reset()` that re-lays it out as the wire
body) and `destination.rs:155-168` (verify). Two traps: the destination hash is **prepended**
and is not in the body, and the signature is **excluded** from what it covers while sitting
mid-body on the wire. A naive "sign the payload" implementation will not interoperate.

**Confidence caveat.** [M]'s enumeration of announce contents is: destination hash, public key,
application specific data, a random blob, an Ed25519 signature of the above. That puts app_data
*before* the random blob (the opposite of the crate) and names one key where there are two. The
manual therefore corroborates **set membership only, not byte order**. The order above rests on
Beechat alone. Confirming it is oracle test #2 (O-5).

Beechat verifies with `verify_strict` ([B] `identity.rs:134-138`), which rejects small-order
and non-canonical keys and R components. That can only make us **stricter** than RNS, never
looser: a liveness risk, not a security one. Recommend plain `verify` for wire compatibility,
plus an explicit degenerate-key check if we want that property. Low-priority oracle probe.

#### 3.3.4 Random hash

Beechat: `SHA256(32 random bytes)[0..10]` ([B] `hash.rs:48-56`, `destination.rs:246-247`).
[M]: "a random blob, making each new announce unique." To a verifier the field is opaque, so
signature interop is unaffected either way, but RNS may give it internal structure (a timestamp
component used for de-duplication or ordering). O-10.

#### 3.3.5 Receiver validation

What Beechat does ([B] `destination.rs:115-174`): packet type is Announce; data >= 148; parse
the Ed25519 key (reject on failure); reconstruct the signed message; `verify_strict`.

What Beechat does **not** do, and retinue should:

- **Recompute the destination hash and compare it to the packet's address field.** Beechat
  computes `address_hash` inside `SingleOutputDestination::new` and then never compares it,
  filing the destination under the *claimed* address ([B] `transport.rs:485`). The signature
  does bind the address (it is the first 16 signed bytes), so this is not cross-peer forgeable,
  but an announcer can squat an address it cannot derive. **Whether RNS drops such an announce
  is unknown** (O-13); the previously-cited manual sentence supporting the check does not exist.
  Recompute and compare anyway: it costs one SHA-256 and it cannot make us wrong.
- **Dedup.** No replay or freshness check anywhere in the crate.
- **Hop limit.** `PATHFINDER_M` is declared and never read.
- **`destination_type == Single`.** Not checked. (Beechat can only *emit* Single announces:
  `Destination::announce` is implemented only for `Destination<PrivateIdentity, Input, Single>`,
  `destination.rs:222-293`.)
- **Context byte.** 0x00 vs 0x0B (path response) is not distinguished. [M]'s announce-handler
  API exposes `is_path_response` and `receive_path_responses`, so the distinction exists on the
  wire; that it is carried by context 0x0B is [I] (O-15).

#### 3.3.6 Ratchets in announces: the biggest gap

[M]: `RATCHETSIZE` = 256 bits; `Destination.enable_ratchets` "will have a small impact on
announce size, adding **32 bytes** to every sent announce"; RNS will "include the latest ratchet
key in announces." That is everything the allowed sources say. Beechat has **zero** ratchet code
(case-insensitive grep across the whole tree: no hits).

app_data is variable-length and unframed, so a 32-byte optional field **cannot** be discriminated
by total length: a ratcheted announce with no app_data is byte-length-identical to an unratcheted
one with 32 bytes of app_data. Some out-of-band signal is therefore structurally required. The
header context flag (bit 5) is the natural candidate; an unassigned context byte (0x0F..0xF9) is
another. **We do not know which, and we will not guess.**

Two candidate body layouts, both parseable at fixed offsets:

```
A: ..‖ rand_hash(10) ‖ RATCHET(32) ‖ sig(64) ‖ app_data
B: ..‖ rand_hash(10) ‖ sig(64) ‖ RATCHET(32) ‖ app_data
```

**They fail in opposite ways, and B is the dangerous one.** Under A, a Beechat-shaped parser
reads `RATCHET‖sig[0..32]` as the signature, verification fails loudly, and the announce is
dropped. Under B, if the ratchet sits immediately before app_data in the *signed* message too,
a Beechat-shaped parser reconstructs a byte-identical signed message (because it treats
everything past the signature as app_data), **the signature verifies**, and the caller is handed
app_data with 32 bytes of ratchet key silently glued to the front. That is a days-long debugging
trap and it is why O-1 blocks all announce code.

### 3.4 Link establishment and the token

#### 3.4.1 Link request: VERIFIED [B], size confirmed by [M] (83 bytes)

The initiator generates a **fresh ephemeral identity: two keypairs**, X25519 and Ed25519
([B] `link.rs:145`). [M] confirms the two-keypair reading.

```
 off  len  value
   0    1  0x02   ifac=0, type1, broadcast, dest_type=Single, packet_type=LinkRequest
   1    1  0x00   hops
   2   16  the DESTINATION's address hash (not the link id)
  18    1  0x00   context
  19   32  LKi_x  initiator ephemeral X25519 public
  51   32  LKi_s  initiator ephemeral Ed25519 verifying
```
Total 83. The initiator's ephemeral Ed25519 key is never used to sign anything in the crate;
its purpose is presumably `Link.identify()` (context 0xFB), which the crate does not implement.

#### 3.4.2 Link ID: CRATE-ONLY, and the manual arguably contradicts it

```
Beechat:
  link_id = SHA256( (meta & 0x0F) ‖ dest_hash[16] ‖ context[1] ‖ data[0..min(64, len)] )[0..16]
```
[B] `link.rs:82-103`. Same construction as the packet hash, except truncated to 16 bytes **and
the payload is clipped to its first 64 bytes** (`link.rs:85-91`).

[M] says: "The link id is a hash of the entire link request packet." That is *not* this
construction: the crate excludes the hops byte and the top four header bits, and clips the
payload. The manual's wording is evidence against the crate, not for it.

The 64-byte clip is load-bearing and suspicious. Combined with `LINK_MTU_SIZE = 3` it reads as
an accommodation for a newer RNS that appends an MTU field after the two keys. **If RNS hashes
the full payload and we clip, the two sides compute different link IDs and the link silently
never forms.** O-4.

#### 3.4.3 Link proof: VERIFIED [B], size confirmed by [M] (115 bytes), field order DISPUTED

The responder generates a fresh ephemeral X25519 secret but signs with the **destination's
long-term Ed25519 key** ([B] `link.rs:176`, `transport.rs:518-523`).

Signed blob, 80 bytes ([B] `link.rs:225-229` emit, `link.rs:481-495` verify):
```
link_id[16] ‖ LKr_x[32] ‖ destination_long_term_Ed25519_verifying_key[32]  [ ‖ mtu[3] ]
```
[M]'s prose names only **two** fields: "an Ed25519 signature of the link id and LKr made by the
original signing key of the addressed destination." The crate signs three. The crate is probably
right (it interoperates in the field), but if it is wrong, every proof we send is rejected and
every proof we receive fails. O-4b.

Wire packet, 115 bytes:
```
 off  len  value
   0    1  0x03   dest_type=Single (NOT Link), packet_type=Proof
   1    1  0x00   hops
   2   16  link_id   <- addressed to the LINK id
  18    1  0xFF   context = LinkRequestProof
  19   64  Ed25519 signature
  83   32  LKr_x  responder ephemeral X25519 public
```
Note the field order **inverts** between the signed blob (`id ‖ LKr ‖ vk`) and the wire
(`sig ‖ LKr`). [M]'s prose lists LKr *before* the signature. The 115-byte total is order-blind
and disambiguates nothing. **Wire field order is an open question too** (O-4c): read bytes
19..51 of a captured proof and check whether they are a valid X25519 point.

Verification uses the destination's **already-known** long-term verifying key
([B] `link.rs:480`), taken from a prior announce. That is a hard ordering requirement on
retinue's link state machine: **you cannot verify a link proof from a destination you have not
heard announce.**

MTU trailer: [B] `validate_proof_packet` (`link.rs:470-493`) rejects only `len < 96` and
appends *all* bytes past offset 96 to the signed blob; the 83-byte sign-data buffer means any
trailer other than exactly 0 or 3 bytes fails with `OutOfMemory`. Lengths 97/98 are silently
treated as the 96-byte form. Beechat itself never emits a trailer. Note that [M]'s 115-byte
proof size implies RNS 1.x does **not** emit the trailer on a 500-MTU interface. Combined with
`LINK_MTU_DISCOVERY = True` [M], this needs a capture on a high-MTU (TCP) interface. O-4.

#### 3.4.4 ECDH and KDF: VERIFIED [B]

```
ikm  = X25519(own ephemeral secret, peer ephemeral public)     32 bytes
salt = link_id                                                 16 bytes
info = EMPTY
okm  = HKDF-SHA256(salt, ikm).expand(&[], 64)                  64 bytes

derived[0..32]  = HMAC-SHA256 signing key
derived[32..64] = AES-256 key
```
[B] `identity.rs:404-410` (the HKDF call), `link.rs:416-425` (salt = link id),
`identity.rs:356-360` (split), `fernet.rs:92` (parameter order proves which half is which).
Both ends are ephemeral: that is the link's forward secrecy.

#### 3.4.5 The token: VERIFIED [B], corroborated by [M]

```
token = IV[16] ‖ AES-256-CBC/PKCS7(ciphertext) ‖ HMAC-SHA256[32]
```
The HMAC covers **IV ‖ ciphertext and nothing else** ([B] `fernet.rs:145-149`). It does **not**
cover the packet header, the destination hash, or the context byte. Those are unauthenticated.
That is a protocol property retinue inherits, not a bug to fix.

No version byte, no timestamp, no base64 ([B] `fernet.rs:37-43`; [M] "No Fernet version and
timestamp metadata fields").

Overhead: **48 bytes + 1..16 PKCS7**. PKCS7 always pads, so a plaintext that is an exact
multiple of 16 costs a whole extra block.

**Two overheads, do not conflate them:**
- **Link** packets use `PrivateIdentity::encrypt` and carry the bare token: **48 bytes**.
- **Single-destination** (link-less) packets are documented as prefixing a 32-byte ephemeral
  X25519 public key: **80 bytes**. But that path in Beechat (`Identity::encrypt`) is dead and
  panics (3.1.6), so the 80 is [I], not [B]-verified.

**Copy neither of these:** the crate's HMAC tag comparison ([B] `fernet.rs:173-179`) uses a
short-circuiting `.find()` and is **not constant-time**. Retinue uses `Mac::verify_slice` or
`subtle`.

#### 3.4.6 Link data, keepalive, RTT: all `meta = 0x0C`, disambiguated ONLY by the context byte

| Packet | Context | Payload |
|---|---|---|
| Link data | 0x00 | token (IV ‖ ct ‖ HMAC) |
| Keepalive | 0xFA | **one plaintext byte**: 0xFF request, 0xFE response |
| Link RTT | 0xFE | token over a MessagePack float |

The keepalive byte is **not encrypted** ([B] `link.rs:351-352` writes it raw; `link.rs:267,272`
reads it raw), and [M]'s 20-byte keepalive size independently confirms this: a token would make
it at least 67 bytes. This plaintext/ciphertext asymmetry inside one destination type is exactly
what a decoder gets wrong.

Bidirectional traffic on an established link is addressed to the same link ID in both
directions ([M]; [B] `link.rs:285`).

#### 3.4.7 The RTT size discrepancy: unresolved

[M] says the link RTT packet is **99 bytes** (= 80 payload bytes = two AES blocks of
ciphertext, i.e. a 17..31 byte plaintext). Beechat's `create_rtt` ([B] `link.rs:382-414`)
MessagePack-encodes an f32 (5 bytes), which through the 48-byte token overhead gives one
16-byte block and an **83-byte** packet. The gap is exactly one AES block. Either RNS's RTT
plaintext is bigger than an f32, or the packet uses a type-2 header (+16). Beechat never
parses an inbound RTT at all, so it has never been tested against a real one. O-14.

This is the **only** row of [M]'s size table that does not reconcile with the crate. Four rows
do (keepalive 20, link request 83, link proof 115, announce 167), plus path request 51 = 19 + 32.

#### 3.4.8 Not implemented anywhere we can see

`LinkIdentify` (0xFB), `LinkClose` (0xFC), `LinkProof` (0xFD, per-packet delivery proof, distinct
from `LinkRequestProof` 0xFF) and `Channel` (0x0E) are constants only in Beechat. `Link::close()`
([B] `link.rs:434-440`) flips local state and **puts nothing on the wire**. Payloads unknown. O-16.

#### 3.4.9 Ratchets and links

[M]: ratcheting is offered so that "asymmetric, **link-less** packet communication can also
provide forward secrecy," on a **per-destination** opt-in basis. Links already have forward
secrecy from the double-ephemeral handshake. **This is real evidence that the link handshake is
ratchet-independent** and that retinue can build the link layer without ratchets. It is [I], and
it is the inference most worth having the oracle disprove early: if the link request is also
addressed to a ratchet key, 3.4.4 changes.

The receiver-side ratchet selection problem (how does a receiver know which of up to 512 retained
ratchet keys a packet used?) is unanswered. Candidates: trial decryption with HMAC check
(consistent with `RATCHET_COUNT = 512` and with `ratchet_id_receiver` being an out-parameter in
[M]'s API), or an explicit id. The claim that `ENCRYPTED_MDU` arithmetic "leaves no room" for a
ratchet id is **not sound** (see 3.6.2) and must not be leaned on.

### 3.5 TCP interface framing

#### 3.5.1 The codec: VERIFIED [B] `iface/hdlc.rs` (97 lines, read in full)

Async-HDLC-style flag delimiting with byte stuffing. **The manual never uses the word "HDLC";
that is Beechat's name.** Describe the bytes, not the name.

```
encode:
  emit 0x7E
  for b in payload:
      if b == 0x7E or b == 0x7D: emit 0x7D; emit b ^ 0x20
      else:                      emit b
  emit 0x7E
```

Only `0x7E` and `0x7D` are ever escaped. **No ACCM** (RFC 1662's control-character escapes are
absent). **No FCS, no CRC, no length prefix, no address/control field, no abort sequence.**

```
payload : 01 00 7E 7D AB
encoded : 7E 01 00 7D 5E 7D 5D AB 7E
encoded_len = 2 + payload_len + count(payload, b in {0x7E, 0x7D})
worst case  = 2 * payload_len + 2
```

Address fields are truncated SHA-256, so roughly 0.8% of payload bytes are a 7E or 7D. **Escapes
occur in real announce traffic.** Fixtures must contain at least one `7d 5e` and one `7d 5d` or
the stuffer is untested.

Decode properties worth copying ([B] `hdlc.rs:62-96`):
1. Bytes before the first `0x7E` are discarded silently (resynchronisation on garbage).
2. The unescape is an unconditional `^ 0x20`, not a table lookup. Be liberal.
3. **Escape state wins over flag detection**: `7D 7E` unescapes to `0x5E` and does *not*
   terminate the frame. This is the single most likely place for a reimplementation to
   desynchronise.

Beechat's encoder emits **both** an opening and a closing flag, so adjacent frames appear as a
doubled `7E 7E`. Whether RNS shares one flag between frames is unknown, and a tolerant decoder
makes it moot:

```
Sync:    discard until 0x7E, then -> InFrame, buf empty
InFrame: 0x7E -> if !buf.is_empty() { yield buf }; buf.clear(); stay InFrame
         0x7D -> Escape
         else -> buf.push(b)
Escape:  buf.push(b ^ 0x20); -> InFrame
overflow (buf > MAX_FRAME): buf.clear(); -> Sync      // required, or a stray 7E is an OOM
```

#### 3.5.2 Client and server are symmetric: VERIFIED [B]

`TcpServer` implements no codec. On `accept()` it hands the socket to the same `TcpClient`
worker ([B] `tcp_server.rs:99-102`, `tcp_client.rs:36-41`). Framing is identical in both
directions; there is no client-only or server-only field. A `TCPServerInterface` fans out to N
per-connection interfaces. [M] corroborates from a third direction: `BackboneInterface` "is
fully compatible with the TCPServerInterface and TCPClientInterface types, and they can be used
interchangably." (BackboneInterface is Linux/Android only, so Mark's Windows oracle uses
TCPServer/TCPClient regardless.)

#### 3.5.3 Handshake / preamble

Beechat sends **none**: it dials and immediately writes its first frame ([B]
`tcp_client.rs:186-193`). No version byte, no magic, no negotiation.

**This does not establish that RNS sends none.** Beechat's decoder discards everything before
the first `0x7E`, so a server-side preamble of any length would be invisible to it and interop
would still appear to work. The crate ships an example dialling the public testnet
(`examples/testnet_client.rs:19-21`), but that is authorial *intent*, not observed interop, and
the crate's only framing test (`tests/tcp_hdlc_test.rs`) contains no assertions at all.

And one sentence from [M] that I cannot square with "no in-band mechanism":

> "When using the `TCPClientInterface` in conjunction with the `TCPServerInterface` you should
> never enable `kiss_framing`, since this will disable internal reliability and recovery
> mechanisms."

If those mechanisms are local (reconnect timers), we are fine. If any part is **in-band bytes**
(a resync marker, a sequence field, replay of a frame truncated by a disconnect), retinue must
reproduce them. O-11, O-12. **Hexdump before writing the codec.**

#### 3.5.4 KISS

[M] documents `kiss_framing` only on `TCPClientInterface`, for soundmodems, and forbids it
between a TCP client and a TCP server. Beechat implements no KISS. **Leave it off** and this
branch disappears. (The public KISS TNC standard uses FEND=0xC0/FESC=0xDB/TFEND=0xDC/TFESC=0xDD,
but RNS's conformance to it is unverified and irrelevant to v0.)

#### 3.5.5 The IFAC trap in the oracle config

If the oracle's interface config carries `network_name`, `passphrase` or `ifac_size`, RNS turns
on IFAC and the frames decode fine at the framing layer while the packets are dropped as
unauthenticated. That looks exactly like a framing bug. **The oracle's TCP interface must have
none of those three options set.**

#### 3.5.6 Beechat TCP defects, do not port

- **TX silently drops oversized frames.** Both the serialize and the encode results are
  consumed with `if let Ok(_)` ([B] `tcp_client.rs:187, 191`); a stuffed frame that overflows
  the output buffer is discarded with no log and no error. Size the output at `2*len + 2`.
- The RX loop re-runs `Hdlc::find` over the whole buffer for every byte and `copy_within`s the
  window per byte: O(n^2), plus questionable window management. Performance and correctness
  smell, not wire fact.
- An unterminated frame and an output-buffer overflow return the **same** error
  (`RnsError::OutOfMemory`, `hdlc.rs:91-93`). Retinue distinguishes them.
- No TCP keepalive anywhere; an accepted (server-side) connection is never re-established after
  a drop, while a dialled one retries every 5 s.

#### 3.5.7 UDP, for contrast: VERIFIED [B]

The UDP interface has **no framing at all**: one datagram, one packet ([B] `udp.rs:93, 144`).
Framing is a stream concern. If RNS's `UDPInterface` is likewise framing-free (unverified), it
is the cleanest framing-free path for R0 fixture capture: dump one datagram and check whether
byte 0 is `0x7E` or a Reticulum header byte.

Note the v0 plan says only "over a raw byte pipe" for R0 and **names no interface type**. Do not
assume `PipeInterface`. If it is used, [M] says RNS "will continuously read and scan its stdout
for Reticulum packets", and "scan" on a stream implies delimiting, so the pipe is probably framed
too, and R1's framing work would then gate R0's done-condition.

### 3.6 Resources and link data

#### 3.6.1 What we know: nothing at byte level

Beechat implements **no resources, no Channel, no Buffer, no request/response**. Grep for
`Resource` across `src/` hits exactly one file: the `PacketContext` enum and its `From<u8>`
impl. Everything in this section below the context codes is [I] and must not be implemented
against.

The context codes themselves are VERIFIED as constants (3.2.4): 0x01 part, 0x02 advertisement,
0x03 part request, 0x04 hashmap update, 0x05 proof, 0x06 initiator cancel, 0x07 receiver cancel;
0x09 request, 0x0A response; 0x0E channel.

All of these ride in ordinary link data packets: `meta = 0x0C`, destination = link ID. **Only
the context byte distinguishes them.**

#### 3.6.2 Link MDU: the number we must not guess

[M] publishes `PLAIN_MDU = 464` and `ENCRYPTED_MDU = 383`. A model that fits:

```
MDU = floor((base - token_overhead) / 16) * 16 - 1
383 = floor((464 - 80)/16)*16 - 1                  // 80 = 32 ephemeral + 16 IV + 32 HMAC
```

**This is a consistency check, not a confirmation.** 464 - 80 = 384 is already a multiple of 16,
so the block-quantisation step is never exercised, and the model collapses to
`base - overhead - 1` with the `-1` as a free parameter fitted to one published integer. The
80-byte term is itself inferred from dead code (3.1.6).

Applying it to a link data packet (overhead 48, no ephemeral prefix) gives two candidates:

| Base assumption | Link MDU |
|---|---|
| Conservative (`PLAIN_MDU` = 464, reserving room for a transport node to grow the header to type 2) | **415** |
| Aggressive (500 - 19 - 1 = 480, type-1 header only) | **431** |

**I will not choose.** A wrong link MDU either wastes ~4% of every packet or overflows the MTU
on the last interface hop. This is Lesson 7 of the v0 plan in its purest form: **ask the oracle
for `link.get_mdu()`.** O-6.

What *is* fixed and verified: per-link-data-packet overhead = **19 (header) + 48 (IV+HMAC) = 67
bytes, plus 1..16 PKCS7**.

[M] on `RNS.Channel.mdu`: "the number of bytes available for a message to consume in a single
send. This value is adjusted from the Link MDU to accommodate message header information." That
confirms (a) RNS exposes a Link MDU as a first-class quantity and (b) the Channel envelope has a
fixed-size header subtracted from it.

#### 3.6.3 Link data packets are unsequenced: INFERRED (strongly)

`Link::handle_packet` dispatches purely on the context byte. There is no sequence number, no
ack, no window, no reorder buffer, no retransmit timer anywhere in the crate's link, and a
ctx-0x00 link payload is exactly a token with no framing bytes around it.

This is **INFERRED, not verified by absence**: Beechat implements 4 of 21 contexts, and ctx 0xFD
(`LinkProof`, "link packet proof") is precisely the per-packet ack path it does not implement.
[M]'s `PacketReceipt.get_status()` returning `DELIVERED` implies that path is live.

The consequence stands regardless: **RNS's reliability lives above the raw link data packet, in
Channel (0x0E) and Resource (0x01-0x07), and RNS already has the byte-stream abstraction**
(`RNS.Buffer` over `RawChannelReader`/`RawChannelWriter`, keyed by a `stream_id`). This answers
the v0 plan's open question 2: **retinue's `AsyncRead`/`AsyncWrite` should be a Channel/Buffer
port, not a shim we invent over raw link data packets.** The raw ctx-0x00 packet stays exposed
as the datagram primitive it is.

#### 3.6.4 Resource transfer: territory map only, all INFERRED

Reconstructed from the seven context codes plus [M]'s API surface (`RNS.Resource`,
`link.set_resource_strategy(ACCEPT_NONE | ACCEPT_APP | ACCEPT_ALL)`, `get_parts()`,
`get_segments()`, `get_progress()`, `is_compressed()`, `auto_compress`). **No field orders,
integer widths, or serialization format are knowable from allowed sources.**

```
sender                                              receiver
  |  ADV  ctx=0x02  {resource hash, sizes, part      |
  |                  count, segments, flags,         |
  |                  part hashmap (first chunk)}     |--> strategy check
  |  REQ  ctx=0x03  {which parts}                    |
  |<-------------------------------------------------|
  |  PART ctx=0x01  {part bytes}  (one per part)     |
  |------------------------------------------------->|
  |  HASHUPDATE ctx=0x04 (hashmap continuation)      |
  |------------------------------------------------->|
  |  PROOF ctx=0x05                                  |
  |<-------------------------------------------------|
  |  CANCEL ctx=0x06 (initiator) / 0x07 (receiver)   |
```

Request/response (0x09 / 0x0A) is likewise unmapped. Reasonable inferences, all unverified: the
path travels as a truncated SHA-256 rather than a string; `request_id` is derived rather than
random; requests or responses larger than the link MDU degrade into Resources (the only reading
under which `RequestReceipt.get_progress()` and `register_request_handler(auto_compress=...)`
make sense); `ALLOW_LIST` gates on the identity revealed by `LinkIdentify` (0xFB).

### 3.9 Channel — reliable, sequenced link messaging (captured 2026-07-17)

The layer beneath `Buffer` (RNS's reliable byte stream). Captured black-box via
`oracle/capture_channel.py`; fixture `tests/fixtures/channel_wire.json`. `Envelope.pack()`
is pure over `(msgtype, sequence, payload)`, so the envelope layout is read directly from its
output; the constants are public class attributes; the packet context is `RNS.Packet.CHANNEL`.

- **Packet context:** `CHANNEL = 14` (`0x0e`). A Channel message is an ordinary link data
  packet (`0x0c 0x00 | link_id | 0x0e | token(envelope)`), same encryption as any link data —
  the token wraps the plaintext envelope below.
- **Envelope layout** (plaintext, big-endian):

  ```
  [ msgtype u16 ][ sequence u16 ][ length u16 ][ payload (length bytes) ]
  ```

  Verified vectors (RNS's own `pack()`): `seq=7,msgtype=0xABCD,"hello"` →
  `abcd 0007 0005 68656c6c6f`; `seq=0,""` → `abcd 0000 0000`; `seq=65535,"AB"` →
  `abcd ffff 0002 4142`. `msgtype` identifies the registered message class; `length` is the
  packed-message length, redundant with the packet length but present.
- **Sequence:** windowed 16-bit, `SEQ_MODULUS = 65536`, `SEQ_MAX = 65535`. Window comparisons
  wrap — retinue's current `channel` uses a monotonic u32 and must move to wrapping u16 for
  wire-compat.
- **Dynamic window (the R4 "dynamic window sizing" deferral, spec'd by constants):** starts at
  `WINDOW = 2`, grows toward an RTT-tiered max — `WINDOW_MAX_SLOW/MEDIUM/FAST = 5/12/48` at RTT
  thresholds `RTT_SLOW/MEDIUM/FAST = 1.45/0.75/0.18 s`, with `WINDOW_MIN_LIMIT_*` floors
  (2/5/16) and `WINDOW_FLEXIBILITY = 4`; `FAST_RATE_THRESHOLD = 10` consecutive successes to
  step up. `WINDOW_MIN = 2`, `WINDOW_MAX = 48`.
- **Acknowledgement — CONFIRMED 2026-07-17 (proof-based).** Captured over a real link
  (`oracle/capture_channel_link.py`, fixture `channel_link.json`): with a channel message sent
  and the receiver staying silent, RNS **retransmitted the identical seq-0 envelope 5 times**.
  So the ack is the **link packet proof**, not an ack envelope — each channel packet is
  proof-requesting, and an unproven sequence is retransmitted. This differs from retinue's
  current explicit `Frame::Ack`, which must go. The *machinery* (sequencing, window, retransmit,
  reorder-buffer) is unchanged; only the ack signal moves from an explicit frame to the link
  proof. The same capture also confirmed the envelope on the real encrypted wire, not just from
  `pack()`: `abcd 0000 000d "channel-hello"`.

**Implication for retinue.** The `channel` module built 2026-07-17 has the right machinery,
tested against the loss oracle, but its own wire. To become RNS-Channel-compatible: (1) swap the
envelope to the layout above under context 14; (2) move seq to wrapping u16; (3) replace explicit
acks with link-proof acks (pending O-18's ack half); (4) adopt the dynamic window. The reliability tests
carry over unchanged — only the codec + ack-source swap. **All four done 2026-07-17/18**: the
envelope, wrapping u16 sequence, proof-as-ack (`on_proof`), and the dynamic window all landed in
`src/channel.rs`, gold-tested against the fixtures.

### 3.10 Buffer — the stream frame over a Channel (captured 2026-07-18)

`Buffer` is RNS's byte stream: it chunks bytes into `StreamDataMessage`s carried as Channel
messages, keyed by a `stream_id` so one Channel multiplexes several streams. Captured black-box
via `oracle/capture_buffer.py`; fixture `tests/fixtures/buffer_wire.json`. `StreamDataMessage.pack()`
is pure over `(stream_id, data, eof, compressed)`, so the frame is read directly from its output.

- **Message type:** `STREAM = 0xff00` (the Channel envelope's `msgtype` for stream chunks).
- **Frame layout** (the envelope *payload*, big-endian):

  ```
  [ u16 header ][ data ]        header = eof<<15 | compressed<<14 | stream_id
  ```

  `stream_id` is the low **14 bits** (`STREAM_ID_MAX = 0x3fff`); the top two bits are the flags.
  The data length is *not* in the frame — it is the enclosing envelope's `length` minus 2. Verified
  vectors (RNS's own `pack()`): `sid=0,"hi"` → `0000 6869`; `sid=16383,"hi"` → `3fff 6869`;
  `sid=7,eof,"AB"` → `8007 4142`; `sid=7,compressed,"AB"` → `4007 4142`.
- **Sizes:** `MAX_DATA_LEN = 423` data bytes per frame, `OVERHEAD = 8` (2 stream header + 6 envelope
  header) — so a full stream packet is 431 bytes of link MDU.
- **Compression:** `pack()` stores `data` **verbatim** even with `compressed=1` — the flag marks a
  bz2 transform applied to `data` *before* framing, not a layout change. So the frame codec is
  compression-agnostic; only a sender that compresses and a receiver that inflates need bz2.
- **EOF:** a frame with the eof bit set ends that `stream_id`'s stream. It may carry final data or
  be empty.

**Implication for retinue — done 2026-07-18.** `channel::StreamFrame` encodes this layout; `Buffer`
now frames every write as a `StreamFrame` under `0xff00`, filters reads by `recv_stream_id`, and
signals `finish()`/`recv_finished()` via the eof bit — gold-tested against the fixture. retinue never
sets `compressed` on send; a compressed frame received from RNS is surfaced
(`had_unsupported_frame`) rather than spliced in as garbage, pending a bz2 receive pass (the one
remaining interop gap, narrow because bz2 rarely shrinks a sub-423-byte chunk).

### 3.11 Link-data proof — the ack a Channel treats as delivery (captured 2026-07-18)

§3.9 established that a Channel packet is proof-requesting and that the *ack is the link packet
proof* — but not the proof's bytes. Captured authoritatively via `oracle/capture_rns_proof.py`
(fixture `rns_link_proof.json`): we sent RNS a proof-requesting Channel packet and read the PROOF
it emitted, then recovered the format by *which key over which message validates the signature*, so
nothing is guessed. (A first attempt inferred the format from whether it silenced RNS's
retransmit; that oracle is confounded by RNS giving up after ~5 resends, so it was discarded.)

- **Packet:** `Proof`-type, `flags = 0x0f` (header-1, destination-type LINK, packet-type PROOF),
  addressed to the **link id** (not the proven packet's hash), context `0x00`, sent unencrypted.
- **Payload — explicit, 96 bytes** (`PacketReceipt.EXPL_LENGTH`):

  ```
  [ full_packet_hash (32) ][ Ed25519 signature (64) ]
  ```

  The signature is over the **full 32-byte** packet hash (`SHA256(masked_flags || destination ||
  context || payload)` — retinue's verified formula, un-truncated). Because the proof is addressed
  to the link, it carries the hash inside to name *which* packet it proves; the sender matches that
  to an outstanding sequence. The implicit 64-byte form is not used here.
- **Signing key:** the prover's **identity** Ed25519 key. RNS (owning the destination) signs with
  its identity; the peer validates against the identity it learned from the announce. Confirmed on
  the wire: the captured signature verifies as `rns_identity_ed25519 over full_hash`.

**Implication for retinue — done 2026-07-18.** `link::data_proof_packet` / `read_data_proof` (and
the `Link::data_proof` / `Link::verify_data_proof` wrappers) build and validate this. A gold test
reproduces RNS's captured proof **byte for byte** — Ed25519 is deterministic, so signing the same
hash with the same identity yields RNS's exact signature — and validates RNS's own proof back. This
is the ack primitive the Channel driver rides: prove a received data packet, and match an inbound
proof's hash to the outstanding sequence it releases. What remains is the driver itself — pumping
`Channel::poll_transmit` on a clock, emitting a proof per delivered packet, and calling `on_proof`
when a proof's hash lands — wiring the reliable stream under `endpoint::LinkStream`.

---

## 4. Open questions for the oracle

Ranked by blast radius: how badly a wrong guess hurts, and how silently.

| # | Question | Cost of a wrong guess |
|---|---|---|
| **O-1** | **Ratchets in announces.** Does a ratchet-enabled destination's announce carry a 32-byte X25519 ratchet key, at what offset (before or after the signature), and is it inside the signed message? Capture an announce from a ratchet-enabled destination with a distinctive app_data (`AAAABBBB`), and one from a ratchet-disabled destination, and diff the raw bytes. | **Catastrophic and silent.** Under layout B a Beechat-shaped parser verifies the signature *successfully* and hands the caller app_data with 32 bytes of ratchet key glued to the front. Days lost. **Blocks all announce code.** |
| **O-2** | **Destination hash KAT.** Ask the oracle for `Destination.hash(identity, "example_utilities", "announcesample", "fruits")` with seed `f0ecbba4...6d6c` (both halves). Expected `2419dca3c93718497b91990373df1503`. | Confirms the entire hashing chain (10-byte name hash, 26-byte preimage, no identity in the name string) in one shot. If it fails, everything downstream is wrong and we learn it on day one. **Cheapest, highest-value test.** |
| **O-3** | **Context flag (bit 5) semantics.** Which packet types set it, and what changes when it is set: extra bytes, reinterpreted bytes, or a semantic hint only? Prime suspect for ratchet signalling. Capture announces and link handshakes with ratchets on/off and MTU discovery on/off; diff header byte 0. | Silent misparse of every flagged packet. Note an unassigned context byte (0x0F..0xF9) is an equally live carrier: do not assume it is bit 5. |
| **O-4** | **Link MTU discovery: does 1.3.8 append 3 bytes to the link request and/or proof, and is the link ID hashed over the full payload or only the first 64 bytes?** Also: is the link-ID preimage really the masked/clipped hash, given [M] says "a hash of the entire link request packet"? Capture a handshake on TCP (high MTU) and on a 500-byte interface, and count bytes: 83/115 means no trailer; 86/118 means it is real. | **Silent total failure.** Wrong link ID means both sides derive different keys and **no link ever forms**, with no error message. |
| **O-4b** | **The proof's signed blob.** Two fields (`link_id ‖ LKr`, per [M]'s prose) or three (`link_id ‖ LKr ‖ destination_verifying_key`, per the crate)? | Every proof we emit is rejected; every proof we receive fails to verify. |
| **O-4c** | **The proof's wire field order.** `sig(64) ‖ LKr(32)` (crate) or `LKr(32) ‖ sig(64)` ([M]'s prose lists LKr first)? Read bytes 19..51 of a captured proof: is it a valid X25519 point? | Same as O-4b, and the 115-byte total does not disambiguate. |
| **O-5** | **The announce signed-message byte order.** The crate's order (`dest ‖ x25519 ‖ ed25519 ‖ name_hash ‖ rand_hash ‖ app_data`) rests on Beechat alone; [M]'s prose puts app_data *before* the random blob. Capture one announce with non-empty app_data and brute-force which candidate blob the signature covers (pure offline computation once we have one real announce). | Every announce we emit is rejected; every one we receive fails. Cheap to settle offline from a single capture. |
| **O-6** | **Link MDU.** `link.get_mdu()` on a fresh link over a 500-MTU interface: 415, 431, or something else? Then send a plaintext of exactly that length and one byte more. | Wastes 4% of every packet, or overflows the MTU on the last hop. Also settles whether the block-quantisation model is real. This is v0-plan Lesson 7. |
| **O-7** | **Does RNS ratchet on links at all?** [M] frames ratcheting as a link-*less*, per-destination feature, so we expect no. If the link request or link KDF touches a ratchet key, section 3.4.4 is wrong. | Rewrites the whole link crypto section. Cheap to ask early. |
| **O-8** | **Ratchet selection on receive.** How does a receiver know which of up to 512 retained ratchet keys a link-less packet used: trial decryption with HMAC check, or an explicit id on the wire? | Blocks link-less encrypted packets to a ratcheting destination. Not needed for R0-R3. |
| **O-9** | **Type-2 address order.** In a transport-forwarded packet, is the transport id the first 16-byte field and the destination the second? The signature covers the destination, so getting it backwards makes every relayed announce fail. Run the oracle as a transport node and capture a forwarded announce; the destination field is identifiable (it must match the known announcer). | Garbage destinations on every forwarded packet. |
| **O-10** | **Hop-count semantics.** Who increments, and when relative to the forwarding decision? Is a packet arriving with hops >= 128 dropped? (1.3.8's changelog mentions a fixed hop-count serialization error on transport.) | Beechat's evidence here is dead code. Endpoint-only impact is modest, but decode must be right. |
| **O-11** | **TCP: does RNS send any bytes on connect, in either direction, before the first frame?** Point RNS's `TCPClientInterface` at a dumb hexdumping listener and record every byte from `accept()`. Is byte 0 `0x7E`? | A preamble is invisible to a resynchronising decoder, so "it works" proves nothing. If it exists, we must emit it. |
| **O-12** | **What are the "internal reliability and recovery mechanisms" that `kiss_framing` disables between a TCP client and server?** In-band bytes, or local reconnect logic? Kill the connection mid-frame, let RNS reconnect, diff the bytes against a clean connection. | If in-band, our TCP framing is incomplete and reconnects corrupt the first frame. |
| **O-13** | **Does RNS drop an announce whose address field != `SHA256(name_hash ‖ identity_hash)[0..16]`?** Hand-craft a correctly-signed announce with an all-zero destination (the signature covers the address, so we can legitimately sign it) and check whether it enters the oracle's path table. | Determines whether address squatting is a real behavior we must mirror. Recompute-and-compare regardless. |
| **O-14** | **Link RTT packet: 99 bytes ([M]) or 83 (crate's construction)?** Capture the ctx-0xFE packet, decrypt with the derived link key, dump the plaintext. | The only [M] size-table row that does not reconcile. Tells us whether we misunderstand the token layout or the RTT payload. |
| **O-15** | **Path response.** Is an announce delivered as a path response distinguished by context byte 0x0B? Issue a path request (destination `rnstransport.path.request`, 51-byte packet = 19 + 32) and dump the context byte of what comes back. Also confirms the real Plain destination hash (expected `6b9f66014d9853faab220fba47d02761`) and the type-2 address order in one experiment. | Cannot distinguish solicited from spontaneous announces. Cheap; settles three questions at once. |
| **O-16** | **Link close (0xFC) and identify (0xFB) payloads.** Both are dead constants in the crate; `Link::close()` sends nothing. Encrypted or plaintext? What plaintext? | Blocks R3's teardown and R4's `ALLOW_LIST`. |
| **O-17** | **Resource wire format, in full.** Advertisement, part, part request, hashmap update, proof, cancel: serialization format, field order, integer widths, flags, hashmap encoding, windowing model, segmentation ceiling, compression algorithm. | **Blocks all of R4.** Nothing is known below the context codes. |
| **O-18** | **Channel envelope (0x0E) and Buffer stream framing.** ~~Sequence-number width, message-type tag, ack/retry scheme, `stream_id` encoding, EOF marker~~. **ANSWERED — Channel 2026-07-17 (§3.9), Buffer 2026-07-18 (§3.10).** Channel: envelope `[msgtype u16][seq u16][len u16][payload]` under context 14, windowed 16-bit seq, dynamic window, **ack/retry = the link packet proof** (5 silent resends of seq 0). Buffer: stream frame `[eof<<15 \| compressed<<14 \| stream_id:14][data]` under msgtype `0xff00`, `MAX_DATA_LEN=423`, eof bit ends a stream. All gold-tested against fixtures `channel_wire.json` / `channel_link.json` / `buffer_wire.json` and implemented in `src/channel.rs`. Only open interop edge: receiving RNS's *bz2-compressed* frames (narrow — bz2 rarely shrinks a sub-423-byte chunk). | Blocks the `AsyncRead`/`AsyncWrite` surface, which 3.6.3 argues should be a Channel port. |
| **O-19** | **Multi-aspect edge cases.** Zero aspects (is the trailing `.` omitted?), an empty-string aspect, a non-ASCII aspect. Beechat takes aspects as a single pre-dotted string and never exercises the join. | Wrong destination hashes for a class of names. Cheap. |
| **O-20** | **Random hash structure.** Are the 10 bytes pure randomness, or is part a timestamp? Capture several announces from one destination seconds apart and look for monotonic structure. | Signature interop is unaffected (the field is opaque to a verifier). Only affects de-dup and freshness. Low. |
| **O-21** | **MDU enforcement on receive.** Does RNS drop an over-MDU packet on ingress, or only refuse to emit one? Is the ceiling 464 or 465? | Determines how strict our decoder should be. Low. |
| **O-22** | **Ed25519 strictness.** Does RNS ever emit signatures that `verify_strict` would reject (small-order A, non-canonical R)? | Liveness only: strictness can make us drop announces RNS accepts, never the reverse. One adversarial fixture. Low. |
| **O-23** | **IFAC derivation.** Exact key derivation from `network_name` + `passphrase`, and the exact byte range signed (bit 7 set or clear? IFAC bytes zeroed or absent?). | Only needed if retinue ever speaks to an IFAC segment. Not v0. |

**Nothing in R0 should be written before O-1, O-2 and O-5 are answered. Nothing in R3 before
O-4/O-4b/O-4c and O-6.**

---

## 5. Implications for the retinue API

Where the wire forces or forbids something in the Rust surface. These are commitments, not
suggestions.

1. **`NameHash` is `[u8; 10]`. Full stop.** The 10-byte truncation is the only form that appears
   on the wire, and Beechat's zero-padded 32-byte name hash silently fails to compare. This is
   the plan's Lesson 5 and it is confirmed in the source (`destination.rs:83-90`).

2. **`PrivateIdentity::from_secret_bytes(&[u8; 64])`, X25519 secret first, Ed25519 signing seed
   second.** Confirmed against the crate on both parse and emit. No hex-string detour
   (plan Lesson 8).

3. **The header's context flag is a first-class `bool`, not part of the propagation type.** Do
   not reproduce Beechat's 2-bit propagation field. Anything else silently misparses.

4. **The address count is structurally tied to the header type.** One enum carrying either one or
   two addresses, never two independent `Option` fields. Beechat's shape lets a `Type2` packet
   with `transport: None` serialize into a frame every peer misparses.

5. **The context byte is preserved raw.** `Context(u8)` with named constants, or an
   `Unknown(u8)` variant. Never normalize an unknown context to 0x00: it changes the packet hash
   and it would erase whatever 1.x uses to signal a ratchet.

6. **Decode is a total function that never panics.** Bound-check the data length; reject
   over-MDU packets as a wire error. Beechat panics on a >2048-byte data field
   (`buffer.rs:100-103`) and on a >32-byte hash output (`hash.rs:15-19`).

7. **IFAC-flagged packets are dropped with a distinct error, never parsed.** The IFAC length is
   not on the wire. Retinue never sets bit 7 in v0.

8. **Announce decoding rejects on malformed keys.** Never `unwrap_or_default()` a verifying key
   (Beechat does, on the live link-proof path, and then hashes the substitute into an identity).
   Recompute the destination hash from the announced identity and name hash and compare it to the
   packet's address field; drop on mismatch, pending O-13.

9. **`Announce::decode` verifies the signature or returns `Err`.** An unvalidated announce is
   unrepresentable, per the plan's R0 surface. The signed message is *not* a contiguous slice of
   the packet: the verifier must splice the 16-byte address field onto the front of the body
   minus the signature.

10. **`max_payload(context)` is a real function, computed from the negotiated link MTU, and it is
    the only way a caller learns a chunk size.** Plan Lesson 7. It cannot be a constant: link MTU
    discovery moves it. Blocked on O-6.

11. **Link handles are objects with their own I/O.** Already decided (plan, Lessons 2/3/4/6/7).
    The wire adds one constraint: **a link proof can only be verified against a destination
    identity we already hold from an announce.** Link establishment therefore *requires* prior
    announce receipt, and the API must make that ordering explicit rather than failing opaquely.

12. **Constant-time MAC verification.** `Mac::verify_slice` or `subtle::ct_eq`. Beechat's
    short-circuiting `.find()` comparison leaks tag bytes by timing. Wire-invisible, free to fix,
    and exactly the kind of defect a clean-room port inherits by reading the reference's shape.

13. **The 32/32 key split everywhere.** `derived[0..32]` = HMAC, `derived[32..64]` = AES-256.
    Beechat's `Identity::encrypt` splits 16/48 and panics; do not copy it, and do not read the
    single-destination encryption path off that function at all.

14. **The link keepalive byte is plaintext.** Do not run it through the token. The 20-byte
    keepalive size in [M] independently proves it.

15. **The stream type (`AsyncRead`/`AsyncWrite`) is a Channel/Buffer port, not a shim invented
    over raw link data packets.** This resolves the plan's open question 2: RNS already has the
    reliability layer and the byte-stream abstraction, and reinventing them below Channel would
    be wire-incompatible. Raw ctx-0x00 link data stays exposed as the datagram primitive it is.
    Blocked on O-18.

16. **Use the manual's link timers (KEEPALIVE 360 s, STALE_TIME 720 s), not Beechat's (5 s / 20 s).**
    Beechat's are a LoRa chat app's product choices, not wire truth.

---

## 6. What changed relative to the source research

For the record, since these were all stated as facts somewhere and are not:

- The expanded name `example_utilities.announcesample.fruits` is **39** bytes, not 38.
- The header context flag is settled by the manual (bit 5), not an oracle question. Only its
  *semantics* are open.
- IFAC derivation is documented (Ed25519 signature over the whole packet), not unknowable.
- The manual **does** document ratchets, and frames them as link-less and per-destination.
- The claim that `ENCRYPTED_MDU` arithmetic "leaves no room for a ratchet id" is unsound and
  must not be used to rule anything out.
- The manual's announce-contents list does **not** corroborate the signed-message byte order.
  It contradicts it (app_data before the random blob).
- The manual's "the link id is a hash of the entire link request packet" is evidence **against**
  Beechat's masked, 64-byte-clipped preimage.
- `PLAIN_MDU = 464` and "DATA 0-465" do not contradict: the difference is the 1-byte minimum
  IFAC reservation.
- Beechat's `Identity::encrypt`, `create_retransmit_packet`, `PathTable::handle_packet` and
  `Interface::mtu()` are all dead code. Anything read off them is inference, not verification.
- Of the manual's six packet sizes, five reconcile with the crate. The link RTT (99 vs 83) does
  not.
- ~~**No wire bytes have been captured.** The oracle harness does not exist yet.~~
  **Superseded 2026-07-13:** the harness exists (`oracle/capture.py`) and the R0 surface is
  settled against real bytes. See section 0. Links (R3) and resources (R4) remain
  uncaptured, so this caution still holds for those sections.
