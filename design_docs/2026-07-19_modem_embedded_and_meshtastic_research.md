# Rust modem, embedded Retinue, and Meshtastic

**Status:** research verdict, 2026-07-19. This refines
[`2026-07-19_heltec_rnode_and_embedded_rust.md`](2026-07-19_heltec_rnode_and_embedded_rust.md).
It does not claim that either firmware exists yet.

## Verdict

| Move | Feasible? | Removes the host? | Best first hardware | Main boundary |
| --- | --- | --- | --- | --- |
| Rust RNode-compatible modem | Yes | No | T114 | Replaces stock modem firmware while Retinue still runs elsewhere |
| Embedded Retinue endpoint | Yes, after a bounded `no_std` split | Yes | T114 for the small profile; V4 for headroom | Replaces both the host stack and modem boundary |
| Reticulum over Meshtastic | Already demonstrated | No | Any supported Meshtastic board | Tunnels fragmented Reticulum packets through the Meshtastic mesh |
| Meshtastic applications over Reticulum | Technically possible as a translator | Depends on where the translator runs | Not a firmware-first task | Meshtastic node, channel, ACK, and routing semantics do not map transparently to Reticulum |

The sequencing correction is important: stock RNode is still the first radio
oracle, but the Rust modem is not a prerequisite for embedded Retinue. After the
stock-device capture and on-air tests, the two moves can proceed independently.

If eliminating a Pi, phone, or laptop is the goal, embedded Retinue is the move
that does it. A Rust RNode remains a modem attached over USB, BLE, or TCP.

## The useful overlap

The two Rust firmware efforts can share hardware work without becoming one
product:

```text
Heltec schematics + Semtech docs + black-box radio captures
                         |
        permissive board and radio primitives
              /                         \
RNode-compatible firmware          embedded Retinue
host protocol + modem policy        node state + radio bearer
```

The shared layer can own pins, SPI, reset, busy and interrupt handling, TCXO,
RF switch and power-amplifier control, radio configuration, entropy access,
flash primitives, and bounded TX/RX queues. It should use `embedded-hal`,
`embedded-hal-async`, and `embedded-io` traits where they fit. Executors remain
in board binaries.

The provenance condition is strict. A permissively licensed shared layer must
be written from hardware documentation, permissive drivers, and black-box
captures before its authors inspect GPL RNode implementation code. Logic
translated from RNode Firmware belongs in the GPL firmware repository and
cannot become the library that MIT/Apache Retinue links into. This is an
engineering boundary, not legal advice.

## Move A: Rusting the modem

### What this move is

The firmware turns a Heltec board into a host-controlled data radio. Retinue or
RNS still owns identity, announces, links, routing, and resources on another
device. The firmware owns:

- USB CDC first, then BLE and optional TCP;
- KISS framing and the RNode control session;
- persisted frequency, bandwidth, spreading factor, coding rate, power, and
  regional limits;
- bounded flow control, errors, readiness, resets, statistics, RSSI/SNR, and
  queue saturation;
- SX1262 configuration, channel activity checks, airtime policy, long-packet
  behavior, transmit scheduling, and receive delivery;
- board pins, TCXO, RF switching, V4 external power handling, boot, update, and
  recovery.

The original RNode hardware page publicly documents KISS framing and a legacy
command table for data, radio parameters, state, flow control, statistics,
randomness, firmware version, and ROM access. That is enough to establish the
shape of an independent client or firmware, but it is not a complete current
RNode 1.86 specification. Current firmware also supports BLE/TCP transports,
airtime controls, multi-radio devices, and newer boards. Exact current command
payloads, state transitions, error behavior, and on-air long-packet behavior
still need either a GPL source port or black-box capture against pinned stock
devices.

The 500-byte Reticulum MTU matters here. Semtech documents special handling for
SX1261/2 packets longer than 255 bytes. Compatibility requires reproducing the
stock RNode behavior, not merely sending raw bytes through `lora-phy`.

### License choices

| Route | License result | Advantage | Cost |
| --- | --- | --- | --- |
| Translate or adapt RNode Firmware | GPLv3 firmware | Fastest route to behavioral fidelity; upstream source is available | Derived code cannot be linked into MIT/Apache embedded Retinue |
| Independently implement observed compatibility | MIT/Apache is plausible | Modem policy and radio bearer can be reused by embedded Retinue | Requires disciplined provenance, hardware captures, and more conformance work |
| GPL shell over a prior permissive radio/BSP layer | GPLv3 firmware plus reusable hardware primitives | Preserves the accepted source-port route while sharing generic board work | RNode-specific scheduler and air behavior remain unavailable to Retinue unless independently specified |

Apache-2.0 and MIT code can be incorporated into a GPLv3 firmware. The reverse
does not preserve an Apache-only combined work. The GNU GPL FAQ treats static
and dynamic linking with a GPL library as a combined work, and the Apache
Software Foundation describes GPLv3 compatibility as one-way.

The present accepted decision remains coherent: `rnode-firmware-rs` can be a
separate GPLv3 source port, and Retinue can use the resulting device across the
byte protocol while staying MIT/Apache. If maximum reuse with embedded Retinue
is now more important than source-port speed, reopen that decision and make the
modem an independently specified permissive implementation before anyone reads
the GPL implementation.

### Target order

1. **T114:** mature nRF52840 Embassy path, native USB, low power, 1 MB flash,
   and 256 KB RAM. Its limits force honest queue sizing.
2. **V3:** known ESP32-S3/SX1262 baseline with 8 MB flash and USB-UART.
3. **V4:** 16 MB flash, 2 MB PSRAM, native USB, changed pins, and a 28 dBm radio
   path that requires board-specific PA policy.

`lora-phy` is a strong driver candidate. It is MIT, `no_std`, built around
`embedded-hal-async`, supports SX1261/2, and has Embassy/nRF52840 examples. It
does not supply the Heltec BSP or RNode modem policy.

### Modem done condition

- The same host conformance suite passes against pinned stock RNode and the
  Rust firmware without host-side special cases.
- Stock and Rust devices exchange 500-byte packets in both directions across
  the selected modulation matrix.
- Invalid settings, busy timeout, reset, reconnect, full queue, duplicate
  frames, and interrupted transmission have deterministic outcomes.
- Frequency, power, airtime, queue, and flow-control policy are persisted
  settings with safe regional caps.
- A reproducible image identifies its board revision, protocol baseline,
  provenance, and license.
- T114 idle, receive, and transmit current are measured on hardware.

## Move B: embedding Retinue

### Current gap

Retinue is closer to a portable protocol library than Python RNS, but it is not
currently embedded firmware:

- the crate does not declare `#![no_std]`;
- `default-features = false` removes Tokio and bzip2, but direct dependency
  defaults still enable `std` in `ed25519-dalek` and `sha2`;
- `Endpoint` is a 1,000-line Tokio shell with spawned tasks, sockets,
  `Arc<Mutex<_>>`, unbounded channels, and growable maps;
- channel, reliable, and resource state still use growable collections;
- resources retain parts in memory and compression uses `std::io`;
- the current bounded reorder window and packet/HDLC MTU checks are useful,
  but they do not bound endpoint routing, link, interface, or resource state.

The crypto choice is not the blocker. The Dalek crates used here support
`no_std` when default features are disabled, and the RustCrypto primitives are
designed for that environment. The blockers are Retinue's collection,
allocation, I/O, runtime, storage, and capacity contracts.

### Required core shape

The embedded boundary should be a deterministic state machine:

```text
Node::ingest(interface, packet, now) -> bounded actions and events
Node::poll(now)                      -> bounded actions and next deadline

shell supplies: clock, entropy, persistence, radio, USB/BLE, and scheduling
```

The first cut can use `no_std + alloc` as a compile and measurement spike. The
T114 release profile still needs fixed capacities or caller-supplied storage so
heap exhaustion is an ordinary typed error. V4 PSRAM can increase configured
limits, but it should not make protocol state unbounded.

Suggested profiles:

| Profile | Included | Excluded initially | Board |
| --- | --- | --- | --- |
| `endpoint-small` | identity, announces, one to four links, reliable channel, direct radio, small persisted messages | transport routing, bzip2, arbitrary in-memory resources | T114 |
| `endpoint-full` | larger link/message tables, streaming resources, USB/BLE management | unbounded routing or resource assembly | V4 |
| `router` | forwarding, bounded route expiry, announce budget, multiple interfaces | unlimited tables | V4 after endpoint proof |

Direct SX1262 access also needs a defined radio bearer. To interoperate with
stock RNodes it must match their modulation, channel access, packet boundary,
long-packet, and receive metadata behavior. This bearer can reuse a permissive
radio layer only if that layer was independently authored. Otherwise embedded
Retinue needs its own black-box-derived compatibility implementation.

### Embedded done condition

- `thumbv7em-none-eabihf` builds a `#![no_std]` T114 endpoint profile, and an
  ESP32-S3 build proves the V4 shell.
- Linker receipts record flash, static RAM, heap high-water mark, and maximum
  future/task size.
- Full link, route, queue, and resource tables return typed capacity errors and
  remain live after rejection.
- Identity and radio settings survive power loss through a versioned atomic
  flash format.
- The board announces, establishes a link, and exchanges reliable data directly
  with pinned RNS and Retinue peers after loss, reordering, and reboot.
- Hardware receipts cover entropy failure, corrupt flash, malformed frames,
  radio busy timeout, regional power caps, and measured current.

## Meshtastic and Reticulum

The phrase can mean two opposite stack orders. They should not be conflated.

### Reticulum over Meshtastic: feasible now

This already exists. `RNS_Over_Meshtastic` is a GPLv3 Python custom interface
that connects to a Meshtastic device over serial, BLE, or TCP and uses the
Meshtastic network as its carrier. Its author reports an expected maximum near
500 bytes per second and explicitly describes it as slower than RNode, with the
benefit that ordinary Meshtastic relays can propagate the traffic.

Meshtastic has now registered `RETICULUM_TUNNEL_APP = 76` in its official
protobuf port registry, with the encoding described as a fragmented RNS packet.
That turns the idea from a hypothetical encapsulation into a recognized
integration lane.

The costs are structural:

- Reticulum's network MTU remains 500 bytes for compatibility.
- Meshtastic's registry explicitly defines the RNS encoding as fragmented. The
  same registry documents a 240-byte ceiling for its raw serial application;
  the tunnel's exact safe fragment size also depends on its metadata and the
  pinned Meshtastic version.
- Meshtastic performs its own flooding, duplicate handling, optional ACK/retry,
  channel policy, and airtime scheduling around Reticulum's own routing,
  encryption, proofs, and reliability.
- Loss of one fragment discards or retries the larger Reticulum packet.
- It still needs Retinue or RNS on a host attached to a Meshtastic radio. It
  does not remove the Pi by itself.

This is useful for announces, short messages, control traffic, bootstrap paths,
and coexistence with an installed Meshtastic mesh. It is a poor first bearer
for resource transfer or browser synchronization. Performance must be measured
under normal Meshtastic traffic rather than inferred from a two-node bench.

For Retinue, keep the first adapter outside the MIT/Apache library. The official
Meshtastic Rust client, protobuf package, Python client, and the existing RNS
interface are GPLv3. A separate GPL bridge process can own those dependencies
and expose a small framed packet pipe or socket to Retinue. The existing Python
project is an interoperability oracle, not source to copy into Retinue. A
process boundary is the strongest practical separation here, but it does not
replace a license review before distribution.

The bridge done condition is:

- exact 500-byte packet round trips over two and three Meshtastic hops;
- bounded fragment count and reassembly memory;
- timeout, checksum, duplicate, reorder, missing-fragment, reset, and queue-full
  tests;
- measured goodput, latency, retransmissions, and airtime beside ordinary text
  and telemetry traffic;
- configurable destination, channel, hop limit, ACK policy, fragment timeout,
  and airtime budget;
- an explicit GPL process boundary and reproducible dependency set.

### Meshtastic applications over Reticulum: possible, but not transparent

A virtual Meshtastic radio could accept `ToRadio` protobufs from existing apps,
translate selected messages into Reticulum destinations, and emit `FromRadio`
events on the receiving side. That does not make a Reticulum node a Meshtastic
radio. The translator must invent mappings for 32-bit node numbers, channels,
group keys, broadcasts, hop limits, ACKs, positions, telemetry, store-forward,
and the Meshtastic node database.

That is a substantial application gateway with lossy semantics. It should be
built only for a specific compatibility need. For Retinue itself, a native
message format or an explicit bridge for selected Meshtastic text, position,
and telemetry messages is cleaner than emulating the full radio API.

## Recommended order

1. Finish the stock-RNode host interface and black-box capture corpus. Prove
   Retinue on air against pinned RNS before changing firmware.
2. Build the permissive Heltec/SX1262 hardware primitives from documentation and
   captures. Do this before GPL source-port work if reuse matters.
3. Run the modem and embedded spikes in parallel:
   - T114 USB CDC + SX1262 + bounded queues for the modem;
   - T114 `no_std` packet, identity, announce, link, and channel build for
     embedded Retinue;
   - V4 native USB, entropy, flash, PSRAM, and conservative PA proof.
4. Choose the modem license deliberately. Keep GPLv3 for a source-derived port;
   choose MIT/Apache only for an independent compatibility implementation.
5. Treat Reticulum-over-Meshtastic as an optional external bridge after the
   direct RNode bearer is measured. It is a compatibility route, not the basis
   of the embedded architecture.

## Sources checked 2026-07-19

- [Original RNode USB and serial command table](https://unsigned.io/hardware/Original_RNode.html)
- [RNode Firmware 1.86 boards and GPLv3 boundary](https://github.com/markqvist/RNode_Firmware)
- [Reticulum interface manual](https://reticulum.network/manual/interfaces.html)
  and [500-byte MTU reference](https://reticulum.network/manual/reference.html)
- [Semtech SX1262 resources and long-packet application note listing](https://www.semtech.com/products/wireless-rf/lora-connect/sx1262)
- [Heltec WiFi LoRa 32 V3/V4 comparison](https://docs.heltec.org/en/node/esp32/wifi_lora_32/index.html)
  and [T114 documentation](https://docs.heltec.org/zh_CN/node/nrf/mesh_node_t114/index.html)
- [Nordic nRF52840 specifications](https://www.nordicsemi.com/products/nrf52840)
- [Embassy](https://github.com/embassy-rs/embassy),
  [`esp-hal`](https://github.com/esp-rs/esp-hal), and
  [`lora-phy`](https://docs.rs/lora-phy/latest/lora_phy/)
- [`ed25519-dalek` `no_std` feature documentation](https://docs.rs/crate/ed25519-dalek/latest/source/README.md)
- [Meshtastic client API](https://meshtastic.org/docs/development/device/client-api/)
  and [official port registry](https://github.com/meshtastic/protobufs/blob/master/meshtastic/portnums.proto)
- [`RNS_Over_Meshtastic`](https://github.com/landandair/RNS_Over_Meshtastic)
  and [official Meshtastic Rust client](https://github.com/meshtastic/rust)
- [GNU GPL linking FAQ](https://www.gnu.org/licenses/gpl-faq.en.html)
  and [Apache-2.0/GPLv3 compatibility](https://www.apache.org/licenses/GPL-compatibility)
