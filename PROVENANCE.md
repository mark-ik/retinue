# Sennet provenance

Sennet is an independent implementation of interoperability with an existing
LoRa mesh messaging protocol. Its auditability depends on keeping observation,
implementation, and distribution boundaries explicit.

## Source boundary

Implementation facts come from three places:

1. Public byte and frame descriptions published as prose or diagrams.
2. Google's public protobuf wire specification. `src/protobuf.rs` is a generic
   reader and writer for that format.
3. Direct black-box observation of bytes emitted or accepted by radios through
   their serial and RF interfaces.

The permissive dependency graph excludes third-party protocol firmware, client
implementations, generated bindings, and implementation-derived API references.
Third-party `.proto` schemas are not inputs to this crate, and `protoc` is not
run against them. Application behavior is authored here from experiments and
public descriptions.

## Radio-bench reconstruction

This is an experimental method, rather than an evidence quorum. A controlled
capture can support the narrow behavior it demonstrates. Repetition tells us
whether that behavior survives another direction, board, firmware build, or
radio implementation.

The intended bench has three reflashable radios whose roles can rotate:

1. A stock firmware oracle that emits or accepts the behavior under study.
2. The independent Rust direct-PHY implementation under test.
3. A second board or firmware path that exposes hardware-specific assumptions.

Each experiment records the actual boards and roles used, firmware path, radio
parameters, direction, input, raw output, and acceptance result. One variable
is changed at a time where practical. The resulting implementation names only
the behavior the experiment makes useful. Other fields remain numbered and
opaque until they are varied.

The transport and text oracle receipts use Tulle direct-PHY firmware on COM6
and stock firmware on COM7. The hardware-portability receipt rotates the third
board into the independent role: Tulle direct-PHY firmware on a Heltec T114 at
COM10 exchanges Sennet packets with the Heltec v4 on COM6. Corrections remain
welcome when a later bench run narrows or contradicts an earlier result.

This record supports an engineering clean-room process. It is not a legal
opinion or certification, and Sennet does not depend on access to counsel.

## Source and firmware licenses

Sennet and the shared radio crates remain available under MIT or Apache-2.0.
The planned downstream combined firmware distributions may be GPLv3, including
the firmware image, corresponding source, and required notices. Permissive code
can flow into that distribution. GPL-derived implementation code does not flow
back into the permissive crate graph. Commercial distribution does not change
that dependency direction.

## Naming and non-endorsement

Sennet is independently named and is not affiliated with or endorsed by any
existing mesh project. It must not be marketed under another project's
trademark.

## Capture log

Observed fixtures live under `tests/fixtures/` and in focused integration tests.
Each records the device, firmware path, radio parameters, capture method, and
claim made from the bytes. Structural captures can retain numbered fields
without asserting a meaning.

## Transport record

The transport implementation in `src/transport.rs` was authored on 2026-07-22
from these published facts:

- Meshtastic's public **Mesh Broadcast Algorithm** documentation publishes the
  16-byte Layer 1 header byte-for-byte: destination, sender, packet ID, flags,
  channel hash, next hop, and relay node. It also publishes the flag bit layout,
  the 237-byte payload ceiling, sync word `0x2B`, and managed-flooding hop-limit
  mutation. <https://meshtastic.org/docs/overview/mesh-algo/>
- Meshtastic's public **Encryption** documentation states that a channel packet
  encrypts its payload with AES-256-CTR while leaving its header clear. It also
  records that channel messages do not have an integrity check.
  <https://meshtastic.org/docs/overview/encryption/>
- The publicly distributed 2025 SSTIC proceedings, **WHAD: build cool wireless
  attacks**, Listing 3 on printed page 148, publishes the remaining mechanical
  detail: the 128-bit initial counter is two little-endian 64-bit words,
  `(packet_id, sender)`, and AES-CTR advances that value as a big-endian counter.
  <https://actes.sstic.org/SSTIC25/sstic-2025-actes.pdf>
- Colin Finck's independently published STM32WL interoperability experiment
  records that the public LongFast channel expands `AQ==` to the 16-byte key
  `1PG7OiApB1nwvP+rz05pAQ==`, and reports successful decryption with it. This is
  the source for AES-128 channel-key support and its public-key fixture.
  <https://pointinthecloud.com/2024-07-24-000000.html>

The SSTIC example's published header values are retained as the header and
nonce test vector. The decrypted bytes are handed to the application layer only
after transport decryption.

`src/packet_id.rs` retains the nonce-producing `(source, packet_id)` state in a
fixed versioned record. It deliberately performs neither random generation nor
storage: callers select a stable source, advance the counter without wrapping,
and persist the advanced record before transmission. The direct-PHY text
example demonstrates that ordering with a flushed state file.

`src/flood.rs` implements only the managed-flood mechanics supported by the
public header record: channel filtering, bounded duplicate suppression by the
published `(source, packet_id)` identity, hop-limit decrement, and relay-node
replacement. It returns a caller-configured delay window and owns no clock or
radio. The direct-PHY capture fixture proves that relaying preserves the
captured ciphertext and nonce identity while changing only the published relay
fields.

On 2026-07-22 stock COM7 sent `tulle direct phy probe 0722`. Tulle direct-PHY
firmware on a Heltec WiFi LoRa 32 v4 at COM6 captured the 49-byte LoRa frame at
906.875 MHz, SF11/BW250/CR4/5, sync `0x2B`, with SNR 9. The raw frame and its
cleartext are retained in `tests/direct_phy_capture.rs`.

The reverse direction used Sennet to seal a 47-byte packet, Tulle to transmit
it from COM6, and stock COM7 to accept it and return a client frame containing
the expected cleartext. This exercises header construction, nonce construction,
AES-128-CTR, sync word, modulation, and raw transmission as one headed path.

On 2026-07-23 the portability receipt used independent Tulle direct-PHY
firmware at both ends: a Heltec T114 on COM10 and a Heltec v4 on COM6. Sennet
sealed and opened public-LongFast text in both directions. T114 to v4 arrived
at -14 dBm / 6.0 dB SNR; v4 to T114 arrived at -84 dBm / 5.0 dB SNR. This
proves the transport and application path across the second MCU/HAL/radio-board
integration. It does not replace the stock COM7 interoperability receipt.

## Application record: envelope and text

Meshtastic's public Port Numbers page describes `portnum` as the application
selector. Colin Finck's public interoperability write-up describes field 1 as
that port, field 2 as its payload, and port 1 as UTF-8 text. The bench captures
independently show the same shape: stock COM7 transmitted readable text under
field 1 value 1, and Sennet decrypted it on COM6.

`src/application.rs` therefore names only this envelope pair and the port-1 text
interpretation. Several initial captures also carried field 9 with value zero.
Its purpose has not been varied, so Sennet leaves it unnamed.

To test whether field 9 was required, Sennet encoded only field 1, field 2, and
the UTF-8 bytes `sennet semantic api 0722`. Tulle direct-PHY firmware transmitted
the resulting 44-byte RF packet from COM6. Stock COM7 decrypted it, reported it
as a text message, rebroadcast it, and emitted a client frame containing the
same text. COM6 captured that rebroadcast. The transmitted RF packet and COM7
client receipt are retained in `tests/direct_phy_capture.rs`.

The headed path was repeated after Tulle gained its reusable Rust direct-PHY
serial link. Sennet's `direct_phy_text` example constructed and transmitted
`sennet rust link 0722` through COM6 without the Python scratch harness. Stock
COM7 accepted and rebroadcast it; the Rust link on COM6 received the rebroadcast
with SNR 9 and Sennet decoded the same text. The radio driver reported RSSI 0 on
this receipt, so that metric is not treated as valid evidence.

## Node identity record

Meshtastic's public User Configuration page names Long Name and Short Name as
user settings and documents the CLI controls for changing each independently.
<https://meshtastic.org/docs/configuration/radio/user/>

On 2026-07-23 Sennet captured a fresh 47-frame client config stream from stock
firmware on COM7. The baseline node-info record carried numeric value
`0xf66afa64`, user ID `!f66afa64`, long name `Meshtastic fa64`, and short name
`fa64`. The official CLI then changed only the long name to
`Sennet NodeInfo Alpha`. A second 47-frame capture changed protobuf leaf
`4.2.2` and left the adjacent ID and short-name leaves unchanged. Position and
telemetry leaves elsewhere in the record also varied with live device state.

The CLI next changed only the short name to `SNIA`. A third capture changed
protobuf leaf `4.2.3` and left the numeric key, user ID, and long-name leaves
unchanged. The CLI's published `--set-owner` and `--set-owner-short` meanings
are recorded here:
<https://meshtastic.org/docs/software/python/cli/#--set-owner-set_owner>

`src/node_info.rs` names only the identity fields supported by those controlled
changes. It keeps additional node-info and user fields opaque. The numeric key
and `!`-prefixed user ID are named from their exact hexadecimal agreement in
all three captures and from the public CLI's node-ID form; they were not varied
independently. The three raw streams remain under `tests/fixtures/`, and
`tests/node_info_capture.rs` is the executable receipt.

The stock RF capture in `tests/direct_phy_capture.rs` has source
`0xf66afa64`, exactly the numeric key in the node-info captures. The executable
receipt ingests the latest names, decrypts that earlier RF packet, and resolves
it to source `Sennet NodeInfo Alpha` / `SNIA`, broadcast destination, and text
`tulle direct phy probe 0722`. This proves the client-facing source/name/text
join. It does not infer names for endpoints absent from the observed directory.
