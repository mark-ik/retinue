# Heltec, RNode, and embedded Rust

**Status:** accepted direction, revised 2026-07-19. This extends R10 in the v0
plan. The firmware direction is an independently authored MIT/Apache radio
workspace, not a GPL source port; implementation has not begun.
This document does not claim that Retinue or Rust RNode firmware currently runs
on these boards. The focused follow-up
[`2026-07-19_modem_embedded_and_meshtastic_research.md`](2026-07-19_modem_embedded_and_meshtastic_research.md)
corrects the project shape: shared board/radio crates support separate
RNode-compatible, native Retinue, and Meshtastic-compatible firmware images.
It also records the optional embedded Retinue-over-Meshtastic image.

## Decision

"Run Retinue on a Heltec" names three different systems. Keep them separate:

1. **Retinue through a Heltec:** Retinue runs on a computer and a Heltec runs
   stock RNode firmware. USB serial, BLE, or TCP carries RNode/KISS frames
   between them. This is the shortest route to the air and the first target.
2. **A Rust RNode:** Retinue still runs on a computer, while a separate Rust
   firmware turns the board into an RNode-compatible modem. This is useful, but
   it is not an embedded Retinue port.
3. **Retinue on the board:** the board owns identity, announces, links,
   reliability, and direct SX1262 radio access. This removes the RNode host
   boundary. It requires an embedded profile of Retinue, not merely another
   interface driver.

System 1 comes first. It gives Retinue real radio evidence and supplies the
compatibility oracle for both firmware efforts. Systems 2 and 3 are separate
follow-ons and can proceed in parallel; a Rust RNode is not a prerequisite for
native embedded Retinue. The Rust RNode is one firmware personality in a
separate, independently authored MIT/Apache radio workspace that Retinue can
reuse. Native embedded Retinue is the system that removes the host.

For new hardware, the choices split by purpose:

- **T114 is the first Rust modem target.** The nRF52840 has a mature
  `embassy-nrf` path, native USB, and a low-power board design. Its 1 MB flash
  and 256 KB RAM require bounded queues and a deliberately small endpoint
  profile.
- **V4 is the first full embedded-Retinue experiment.** Its ESP32-S3, 16 MB
  flash, and 2 MB PSRAM give the current implementation more room. Its newer
  board support and 28 dBm radio path create more board-specific work.
- **V3 is the conservative ESP32 baseline.** It has less memory than V4 but is
  older, simpler, and already supported by current RNode firmware. Use it when
  it is already on hand or when V4's extra memory and high-power path are not
  needed.

An on-air test needs two radios. A T114 plus a V3 or V4 exercises both MCU
families; two matching boards reduce the first bring-up variables.

## Board fit

| Board | Hardware relevant here | Stock RNode | Rust path | Best fit | Main constraint |
| --- | --- | --- | --- | --- | --- |
| Heltec WiFi LoRa 32 V3 | ESP32-S3N8, SX1262, 8 MB flash, Wi-Fi, BLE, USB-UART | RNode 1.86 lists it | `esp-hal`; use its async support only where it earns its cost | Stock modem or conservative ESP32 Rust target | No PSRAM and less headroom for a full node |
| Heltec WiFi LoRa 32 V4 | ESP32-S3R2, SX1262 radio path, 16 MB flash, 2 MB PSRAM, Wi-Fi, BLE, native USB | RNode 1.86 lists it | `esp-hal`; executor integration must be pinned by a board spike | Full embedded-Retinue prototype | New pin/radio/power BSP; the advertised 28 dBm path is not generic SX1262 setup |
| Heltec Mesh Node T114 | nRF52840, SX1262, BLE 5, USB, lithium and solar inputs | RNode 1.86 lists it | `embassy-nrf` first; RTIC or a polling loop remain viable | Low-power Rust modem and bounded field endpoint | 1 MB flash and 256 KB RAM; no Wi-Fi |

Heltec's V4 comparison says it removes the CP2102 used by V3. Treat V4 USB as
a native-USB firmware responsibility rather than assuming the V3 serial path.
Radio frequency, bandwidth, spreading factor, coding rate, transmit power,
queue sizes, route limits, and announce budget must be persisted settings or
deployment profiles. They must not become board constants. A regional profile
must cap output power and airtime even when the board can transmit above that
cap.

## First system: stock RNode as the radio

Current stable RNode firmware 1.86 explicitly lists Heltec V3, V4, and T114 and
is installable with `rnodeconf --autoinstall`. The Reticulum 1.3.8 manual accepts
RNode connections over serial, TCP, and BLE, then configures radio parameters on
the interface. Retinue should use that existing modem boundary before owning the
SX1262.

The host implementation has three pieces:

1. `iface::kiss`: a sans-I/O KISS encoder and deframer. It owns FEND/FESC
   transposition and command-byte framing. It must remain distinct from the
   existing HDLC codec.
2. `iface::rnode`: the RNode control session. It applies radio settings, observes
   readiness and errors, implements flow control, and passes data frames to the
   packet codec.
3. Host transports: Tokio serial first, then BLE, with TCP useful on Wi-Fi RNode
   builds. Transport I/O stays outside both codecs.

The current `Endpoint::attach_interface()` seam accepts decoded `Packet`s, which
is sufficient for a host-side RNode pump. The pump decodes inbound RNode data to
`Packet`, delivers it to the interface sink, and reverses the path outbound.
This gets on air without changing Endpoint ownership.

### Stock-RNode done condition

- Two supported Heltec boards run a pinned RNode firmware release.
- Retinue configures each modem from persisted settings and rejects invalid or
  unsupported settings visibly.
- A Retinue endpoint and the current pinned RNS oracle exchange announces, establish a
  link, and transfer a reliable stream in both directions over LoRa.
- Disconnect, malformed frame, modem reset, queue saturation, and packet loss
  have deterministic tests and observable errors.
- The radio run records board revision, firmware version, frequency, modulation,
  power, packet counts, retries, and received signal data when the modem exposes
  it.

Before this is called deployable, the v0 plan's on-air gate still applies:
cryptographic randomness, reliable link defaults, bounded queues and frames,
resource retry/cancellation, dynamic flow control, announce airtime budgeting,
and route expiry. A working serial exchange alone does not satisfy the gate.

## Second system: the independent Rust RNode-compatible firmware

**Revised decision, 2026-07-19:** build an independently specified
RNode-compatible firmware in a separate MIT/Apache Rust radio workspace. RNode
Firmware 1.86 remains the first black-box compatibility baseline. This is not a
source translation and must not use GPL implementation code as a donor.

A Rust modem is plausible on all three boards. Its smallest useful form is:

```text
USB CDC / BLE / TCP
        |
RNode control + KISS data
        |
bounded TX/RX scheduler and channel-activity checks
        |
SX1262 driver + board pins, TCXO, RF switch, and PA policy
```

Start with USB CDC, exact radio configuration, raw send/receive, status, and
flow control. Display, GPS, bootstrap console, Wi-Fi, and device menus are later
features. They should not hold the modem interoperability gate open.

The first firmware target is T114. V3 follows as the conservative ESP32-S3
target; V4 follows after its native USB and high-power frontend are understood.
Board support lives behind explicit BSP modules so the protocol and scheduler
do not accumulate pin-condition branches.

[`lora-phy`](https://docs.rs/lora-phy/latest/lora_phy/) is the first driver to
spike. It is `no_std`, uses `embedded-hal-async`, supports SX1261/2, has nRF52840
and Embassy examples, and keeps board-specific control behind an interface
variant. It still needs explicit Heltec implementations for pins, reset, busy,
DIO, TCXO, RF switching, and any external power amplifier. V4's advertised
28 dBm output exceeds the generic SX1262 high-power range exposed by the driver,
so the high-power frontend must be understood from the board schematic and
tested with conservative defaults.

### Repository and license boundary

The separate workspace holds generic board, SX1262, queue, scheduling,
persistence, and transport crates plus distinct RNode and
Meshtastic-compatible protocol crates. Retinue consumes the generic embedded
contracts and supplies its own `no_std` node state machine. Firmware binaries
compose those parts without making the common crate aware of either protocol.

The provenance rules are operational:

- board and radio code comes from hardware documentation and permissive
  embedded dependencies;
- RNode behavior comes from the public legacy command table and captures made
  against pinned stock devices;
- contributors implementing permissive protocol code do not translate or adapt
  GPL RNode or Meshtastic firmware source;
- Retinue's host implementation and capture corpus land before implementation
  work begins, and release notes pin the stock baseline being matched;
- cross-repository tests flash artifacts and treat stock and Rust firmware as
  external devices.

This separation lets Retinue use stock or Rust RNodes interchangeably while
also reusing the independently authored radio scheduler in native firmware.

The same workspace can produce a third, Meshtastic-compatible node image.
Meshtastic publicly documents its raw on-air header, radio settings, encryption,
managed flooding, ACK/retry, next-hop routing, and client API, and its official
hardware registry recognizes a non-Meshtastic implementation that supports the
same frame format. The complete protobuf schemas remain GPLv3, so the
permissive project must not import or generate from them. Seek a permissive
schema/specification grant, or use a separately authored field registry and
black-box corpus subject to legal review.

A single SX1262 should run one selected personality at a time. A reliable
simultaneous RNode/Reticulum and Meshtastic gateway needs two radios. An optional
V4 image can instead run embedded Retinue over the Meshtastic bearer using the
registered `RETICULUM_TUNNEL_APP = 76`; that removes the host but adds a second
mesh/retry layer and fragment reassembly.

### Rust-modem done condition

- The same host-side `iface::rnode` tests pass unchanged against stock RNode and
  the Rust firmware.
- A stock RNode and Rust RNode exchange packets in both directions at every
  supported modulation setting selected for the first release.
- USB reset/reconnect, radio busy timeout, queue saturation, invalid settings,
  and interrupted transmission recover without reboot loops or silent loss.
- Release artifacts identify the exact board revision and license, and a
  reproducible build produces the flashed image.
- Idle, receive, and transmit current are measured on hardware. The T114 target
  must demonstrate sleep between radio or host events before it is called a
  low-power firmware.

## Third system: Retinue on the board

The wire modules being free of Tokio is helpful but not yet an embedded port.
`Endpoint` and the interface seam use Tokio tasks, unbounded MPSC channels,
`Arc<Mutex<_>>`, `std::collections`, sockets, and `std::time`. Channel, routing,
and resource state use growable maps and queues. Resources are assembled in
memory, and compression uses the `bzip2` I/O API. The crate does not declare
`#![no_std]`. Its current `no-default-features` promise covers part of the codec
surface, not a live embedded node.

The durable boundary is an executor-neutral node state machine:

```text
                    +---------------------------+
inbound Packet ---> | Node::ingest(iface, now)  | ---> actions/events
timer tick -------> | Node::poll(now)            | ---> outbound Packets
                    +---------------------------+
                         no I/O, no executor

Tokio host shell          Embassy/RTIC/polling firmware shell
TCP / serial / BLE        USB / BLE / SX1262 / flash
```

The node owns protocol state. Shells own clocks, entropy, persistence, I/O,
task spawning, and bounded delivery. This replaces the current assumption that
the router itself is a spawned Tokio task. It also prevents Embassy from
becoming a public Retinue dependency.

Use feature gates before multiplying crates. Split packages only when the
embedded target can compile a meaningful subset:

- `core`: `no_std` wire types and cryptography, with `alloc` isolated and
  measured;
- `node`: executor-neutral link, channel, announce, and bounded route state;
- `host`: the present Tokio Endpoint and TCP/RNode adapters;
- `firmware`: board applications and BSPs, outside the Retinue library crate if
  their license differs.

Every collection needs an explicit capacity or a storage trait. Every timeout
needs an injected monotonic clock. Key generation and AES IVs need a CSPRNG
supplied by the shell. Identity and settings need an atomic flash format with
versioning and recovery. Resources need streaming storage and bounded part
windows; the T114 cannot make arbitrary resource size proportional to RAM.

### Runtime choice

Embassy is an implementation choice, not the architecture:

- On T114, use `embassy-nrf` first. Embassy directly maintains the nRF52 HAL,
  USB is available through `embassy-usb`, and `lora-phy` already demonstrates
  the relevant nRF52840/SX126x shape.
- RTIC is a credible T114 alternative when interrupt priority and static task
  scheduling matter more than async I/O composition. The nRF52840 is
  Cortex-M4, which RTIC supports. A small polling loop is also enough for the
  first USB/SX1262 modem.
- On V3/V4, use `esp-hal` for the board and peripheral layer. ESP32-S3 is
  supported, including blocking and async peripheral APIs, but the executor and
  radio ecosystem are moving. Pin the complete toolchain after a USB + SPI +
  GPIO-interrupt + entropy spike. A blocking loop is preferable to coupling the
  protocol core to unstable executor integration.

Do not build a common Embassy abstraction across Espressif and Nordic. Share
`embedded-hal`, `embedded-hal-async`, and `embedded-io` traits at the driver
edge; keep executor glue in each firmware binary.

### Embedded-Retinue profiles

Start with explicit capability profiles rather than pretending each board runs
the desktop feature set:

| Profile | Contents | First board |
| --- | --- | --- |
| `endpoint-small` | identity, announces, one or few links, reliable channel, bounded small resources, direct radio | T114 |
| `endpoint-full` | larger tables/resources plus BLE or Wi-Fi management | V4 |
| `router` | forwarding, route expiry, announce budget, multiple logical interfaces | V4 after endpoint-full |

The T114 profile should omit transport-node routing and bzip2 initially. Those
can return only after flash/RAM receipts show room. V4 PSRAM is useful for
experiments, but PSRAM must not excuse unbounded protocol state.

### Embedded-Retinue done condition

- A `thumbv7em-none-eabihf` build compiles the selected Retinue node profile with
  `#![no_std]`; a separate ESP32-S3 target build proves the V4 profile.
- Linker output records flash, static RAM, heap high-water mark, and worst-case
  task/future size. Capacity exhaustion returns a typed error and is tested.
- The board creates or loads an identity, announces directly over SX1262,
  establishes a link with the current pinned RNS oracle or host Retinue, and exchanges reliable data
  after induced loss and reboot.
- Radio and protocol settings survive power loss atomically and can be changed
  without reflashing firmware.
- Fuzzed frames, a full route table, a full queue, entropy failure, flash
  corruption, and resource cancellation have bounded outcomes.
- The T114 receipt includes idle/receive/transmit current. The V4 receipt includes
  native USB recovery and verified PA/power limits.

## Ordered gates

1. **Hardware receipt:** flash stock RNode on two boards and record exact board,
   firmware, and host connection behavior.
2. **Host codec:** land KISS fixtures and a bounded sans-I/O codec.
3. **RNode session:** configure and exchange frames with a stock device over
   serial; add BLE after serial is stable. Tag the black-box host implementation
   and its capture corpus before permissive compatibility work begins, and keep
   that implementation team unexposed to upstream firmware source.
4. **On-air correctness:** satisfy the reliability, entropy, capacity, airtime,
   and route-lifetime gate; pass RNS interoperability over actual LoRa.
5. **Shared hardware foundation:** prove the permissive T114 board, SX1262,
   settings, queue, and scheduler primitives from hardware documentation and
   black-box captures.
6. **Parallel firmware spikes:** prove the independent T114 RNode-compatible
   image, a minimum Meshtastic-compatible image, and Retinue identity, packet,
   announce, link, and channel on nRF52840 with measured memory. The protocol
   personalities share hardware crates but do not depend on one another.
7. **V4 spike:** prove native USB, SPI, DIO interrupt, entropy, flash settings,
   PSRAM if used, and conservative radio output before choosing its executor.
8. **Native endpoint:** replace RNode in one board with the executor-neutral node
   and direct radio shell; retain stock RNode as the interoperability peer.
9. **Optional embedded Meshtastic bearer:** on V4, benchmark fragmented 500-byte
   Reticulum packets through the independent Meshtastic personality while
   ordinary text and telemetry traffic are present.

## Sources checked 2026-07-19

- [Heltec WiFi LoRa 32 version comparison](https://docs.heltec.org/zh_CN/node/esp32/wifi_lora_32/index.html)
  and [hardware update log](https://docs.heltec.org/en/node/esp32/wifi_lora_32/hardware_update_log.html)
- [Heltec Mesh Node T114 documentation](https://docs.heltec.org/zh_CN/node/nrf/mesh_node_t114/index.html)
- [Nordic nRF52840 product specification](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/keyfeatures_html5.html)
- [RNode Firmware stable repository and supported boards](https://github.com/markqvist/RNode_Firmware)
- [Reticulum 1.3.8 interface manual](https://reticulum.network/manual/interfaces.html)
- [Embassy repository and supported HALs](https://github.com/embassy-rs/embassy)
- [Espressif `esp-hal`](https://github.com/esp-rs/esp-hal)
- [`lora-phy` documentation](https://docs.rs/lora-phy/latest/lora_phy/)
- [RTIC target architectures](https://rtic.rs/dev/book/en/internals/targets.html)
- [Meshtastic client API](https://meshtastic.org/docs/development/device/client-api/)
  [mesh algorithm](https://meshtastic.org/docs/overview/mesh-algo/), and
  [official port registry](https://github.com/meshtastic/protobufs/blob/master/meshtastic/portnums.proto)
- [Official Meshtastic protobuf repository and GPLv3 license](https://github.com/meshtastic/protobufs)
