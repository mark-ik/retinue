# Heltec, RNode, and embedded Rust

**Status:** accepted direction, 2026-07-19. This extends R10 in the v0 plan.
The separate GPLv3 Rust RNode port is a decision; implementation has not begun.
This document does not claim that Retinue or Rust RNode firmware currently runs
on these boards. The focused follow-up
[`2026-07-19_modem_embedded_and_meshtastic_research.md`](2026-07-19_modem_embedded_and_meshtastic_research.md)
corrects the sequencing: after the stock-RNode oracle, the modem port and native
embedded Retinue are independent moves that can proceed in parallel. It also
records the independently specified permissive option and the existing
Meshtastic tunnel.

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
native embedded Retinue. The Rust RNode is a committed, separately licensed
project, not code folded into Retinue. Native embedded Retinue is the system
that removes the host.

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
- A Retinue endpoint and the RNS 1.3.8 oracle exchange announces, establish a
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

## Second system: the separate Rust RNode port

**Decision, 2026-07-19:** port RNode Firmware to Rust under GPLv3. The working
repository name is `rnode-firmware-rs`. It is a separate Git repository and
release product, with RNode Firmware 1.86 as its initial compatibility baseline.
The name can change before publication without changing this boundary.

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

RNode Firmware is GPLv3, and the Rust port is GPLv3. It can read, translate, and
adapt upstream source while retaining its license, notices, and corresponding
source obligations. This is an open port rather than a clean-room
reimplementation.

The boundary is operational as well as organizational:

- `rnode-firmware-rs` contains the derived firmware, board support, boot and
  update machinery, and firmware-side conformance tests. It is GPLv3.
- Retinue contains its RNode/KISS host interface under Retinue's existing
  MIT/Apache license. It does not import or link firmware code.
- The integration boundary is the RNode byte protocol over USB, BLE, or TCP.
  Cross-repository tests flash a firmware artifact and treat it as a device.
- Retinue's initial host implementation and capture corpus land and are tagged
  before contributors inspect upstream implementation for the port. That gives
  the host driver a truthful chronological black-box record. Once port work
  starts, the project must not claim its contributors remain unexposed to the
  firmware source. GPL source-derived logic stays in the firmware repository;
  Retinue fixtures record observed device traffic rather than copied code.
- Release notes pin the upstream RNode version whose behavior is implemented.
  Upstream changes are reviewed and ported deliberately rather than followed
  from an unpinned branch.

This separation lets Retinue use stock or Rust RNodes interchangeably without
making firmware a library dependency or changing Retinue's license. It is a
source and build boundary, not an attempt to hide the port's derivation.

An independent MIT/Apache RNode-compatible implementation is also possible in
principle, but it is a different project discipline from this accepted GPL
source port. It cannot translate or adapt GPL firmware code. The focused
research note explains why that route becomes attractive if modem policy must
be reused by MIT/Apache embedded Retinue.

Meshtastic is now more than a hypothetical alternative bearer. Its official
port registry assigns `RETICULUM_TUNNEL_APP = 76` to fragmented RNS packets,
and the GPLv3 `RNS_Over_Meshtastic` project demonstrates the tunnel. It is much
slower than direct RNode, adds a second routing/retry layer, and still requires a
host Reticulum implementation attached to a Meshtastic radio. Treat it as a
compatibility bridge, not a substitute for embedded Retinue. MeshCore and
LoRaWAN still need their own explicit encapsulations. A generic KISS TNC is
closer to RNode, but it lacks RNode's standard radio-control session and needs a
deployment-specific configuration path.

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
  establishes a link with RNS 1.3.8 or host Retinue, and exchanges reliable data
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
   and its capture corpus before reading upstream firmware implementation.
4. **On-air correctness:** satisfy the reliability, entropy, capacity, airtime,
   and route-lifetime gate; pass RNS interoperability over actual LoRa.
5. **Shared hardware foundation:** before GPL implementation exposure, prove the
   permissive T114 board and SX1262 primitives from hardware documentation and
   black-box captures if code reuse with embedded Retinue matters.
6. **Parallel firmware spikes:** create the separate GPLv3 RNode firmware
   repository and prove T114 USB CDC + SX1262; independently compile Retinue
   identity, packet, announce, link, and channel on nRF52840 with measured
   memory. Neither spike waits for the other.
7. **V4 spike:** prove native USB, SPI, DIO interrupt, entropy, flash settings,
   PSRAM if used, and conservative radio output before choosing its executor.
8. **Native endpoint:** replace RNode in one board with the executor-neutral node
   and direct radio shell; retain stock RNode as the interoperability peer.
9. **Optional Meshtastic bridge:** benchmark fragmented 500-byte Reticulum
   packets under ordinary Meshtastic traffic through a separate GPL adapter.

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
  and [official port registry](https://github.com/meshtastic/protobufs/blob/master/meshtastic/portnums.proto)
- [`RNS_Over_Meshtastic`](https://github.com/landandair/RNS_Over_Meshtastic)
