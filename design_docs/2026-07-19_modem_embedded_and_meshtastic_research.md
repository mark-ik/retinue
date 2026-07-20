# Independent Rust radio firmware and embedded Retinue

**Status:** research direction, revised 2026-07-19. This replaces the earlier
interpretation of a GPL source port beside an unrelated embedded Retinue port.
None of the firmware described here exists yet.

## Verdict

The useful project is an independently authored, MIT/Apache Rust radio
workspace with a shared embedded crate and distinct protocol personalities:

| Personality | What runs on the board | Removes the host? | First target |
| --- | --- | --- | --- |
| RNode-compatible modem | RNode host protocol, modem policy, and SX1262 | No | T114 |
| Native Retinue node | Retinue identity, links, routing profile, and SX1262 | Yes | T114 small profile; V4 full profile |
| Meshtastic-compatible node | Meshtastic radio framing, crypto, mesh behavior, and client API | Yes for Meshtastic use | T114 single-purpose image |
| Retinue over Meshtastic | Embedded Retinue plus the Meshtastic bearer and fragmentation | Yes | V4 experiment |

This is more coherent than making the modem a GPL source port. The RNode,
Retinue, and Meshtastic-specific behaviors remain separate, while the expensive
board, radio, scheduling, persistence, and capacity work is shared.

"Could also run Meshtastic" should initially mean that the same crates can
produce a Meshtastic-compatible firmware image. It should not mean that one
SX1262 continuously participates in RNode/Reticulum and Meshtastic networks at
the same time. The protocols can require different frequencies, modulation,
framing, channel access, and receive schedules. A single radio can listen to
only one configuration at a time. Runtime time-slicing would miss traffic and
make airtime policy difficult; reliable simultaneous gateway service needs two
radios.

Use build-time firmware personalities first. A persisted boot selection can
come later. Bundling every personality into every T114 image would spend its
limited flash and RAM without improving interoperability.

## The options, collapsed

Several of the apparent options differ only in which firmware is on the radio
and where Retinue runs:

| Option | Board runs | Retinue runs | Hostless? | License consequence |
| --- | --- | --- | --- | --- |
| Native embedded Retinue | Custom Retinue firmware | Board | Yes | MIT/Apache target |
| Independent `rnode-rs` | Custom RNode-compatible modem | External computer or phone | No | MIT/Apache is plausible with independent provenance |
| Stock RNode | GPL RNode firmware | External computer or phone | No | Clean device boundary; Retinue stays MIT/Apache |
| Stock Meshtastic | GPL Meshtastic firmware | External host through an adapter | No | Adapter is GPL if it uses official schemas/client code |
| Embedded Retinue over Meshtastic | Retinue and Meshtastic bearer in one image | Board | Yes | GPLv3 if it uses official schemas; MIT/Apache only with permissively licensed or independently specified schemas |
| Official Meshtastic Rust crate | Nothing embedded; it is a Tokio desktop client | External host | No | GPLv3 host adapter; not a firmware foundation |
| MeshCore firmware | Stock or custom MeshCore node/modem | External host unless Retinue is composed into the image | Depends | MeshCore is MIT and can be reused in the permissive workspace |

This leaves four distinct architectures:

1. native Retinue directly over the shared radio layer;
2. an RNode modem, stock or independently implemented, with Retinue elsewhere;
3. a Meshtastic carrier, stock with a host adapter or combined with embedded
   Retinue;
4. a MeshCore carrier or compatibility personality.

The official Meshtastic Rust crate does not add a fifth embedded route. It is a
GPLv3, Tokio-based desktop client for USB serial, TCP, and optional BLE. It is
useful inside a GPL host bridge and unsuitable as the `no_std` radio workspace.

MeshCore is not the same licensing story as Meshtastic. Its embedded C/C++ core
and example KISS modem are MIT. The Rust workspace can link it through a narrow
C ABI, port selected pieces to Rust under MIT, or independently implement a
compatible personality. The architectural question remains whether Retinue
benefits from MeshCore's routing or merely needs its installed network as a
bearer; placing one mesh router inside another should be a deliberate
compatibility mode.

## Workspace boundary

Keep the radio project independent of Retinue. Retinue supplies its eventual
`no_std` node state machine; the radio project supplies reusable hardware and
firmware shells:

```text
                    MIT/Apache radio workspace

Heltec BSPs + SX1262 + clock + entropy + flash + bounded radio scheduler
                               |
              +----------------+----------------+
              |                |                |
       RNode modem       Meshtastic node   Retinue radio shell
       USB/BLE/TCP       mesh + client API       |
                                            retinue-core

optional later image: Meshtastic node + port 76 bearer + retinue-core
```

A plain initial workspace layout is:

```text
crates/radio-core          traits, profiles, queues, metadata, policy
crates/sx126x-radio        permissive SX126x driver integration
crates/heltec-t114         pins, USB, BLE, flash, entropy, power
crates/heltec-v3           ESP32-S3 board support
crates/heltec-v4           native USB, PSRAM, RF frontend and power policy
crates/rnode-compat        KISS/control session and modem behavior
crates/meshtastic-compat   independently specified radio and mesh behavior
firmware/rnode             host-controlled modem image
firmware/meshtastic        Meshtastic-compatible node image
firmware/retinue           native Retinue image
firmware/retinue-mesh      optional Retinue-over-Meshtastic image
```

The names are descriptive placeholders, not product branding.

The common crate owns:

- radio profiles and validated regional limits;
- SPI, reset, busy, interrupt, TCXO, RF-switch, and PA control;
- bounded TX/RX queues, receive metadata, channel activity, scheduling, and
  airtime accounting;
- injected clock, entropy, persistence, and transport traits;
- board capabilities and typed capacity or hardware failures.

It does not own RNode commands, Retinue packets, Meshtastic frames, routing,
application ports, or an async executor. Board binaries can use Embassy, RTIC,
`esp-hal` async support, or a polling loop without leaking that choice into the
protocol crates.

An interface in this neighborhood is sufficient:

```rust
trait Radio {
    fn configure(&mut self, profile: &RadioProfile) -> Result<(), RadioError>;
    fn receive(&mut self, now: Instant) -> Result<Option<ReceivedFrame>, RadioError>;
    fn transmit(&mut self, frame: &[u8], policy: TxPolicy) -> Result<(), RadioError>;
}

trait Protocol {
    fn ingest(&mut self, frame: ReceivedFrame, now: Instant) -> Actions;
    fn poll(&mut self, now: Instant) -> Actions;
}
```

The actual API must make returned action storage and queue capacity explicit;
the sketch only records the ownership split.

## License and provenance

An MIT/Apache result is plausible only as an independent implementation. Do not
translate, adapt, or link code from RNode Firmware or official Meshtastic
firmware. Both are GPLv3. Keep these inputs distinct:

| Input | Safe role in the permissive project |
| --- | --- |
| Heltec schematics and MCU/Semtech documentation | Hardware implementation |
| MIT/Apache embedded drivers such as `lora-phy` | Reusable dependency or donor |
| Published protocol documentation | Independent specification |
| Captures produced by pinned stock devices | Conformance fixtures and black-box oracle |
| GPL RNode or Meshtastic source | External oracle only; not implementation input |
| GPL Meshtastic `.proto` files and generated Rust package | Do not copy, generate from, or depend on them |

The Meshtastic boundary needs special care. The official documentation publicly
specifies much of the on-air protocol: a 16-byte raw header, sync word `0x2B`,
encrypted protobuf payload, a 237-byte data ceiling, CSMA/CA, managed flooding,
ACK/retry behavior, and the version 2.6 next-hop scheme. Its client API also
documents the serial/TCP framing and `ToRadio`/`FromRadio` flow. That is enough
to begin an independent compatibility effort.

The complete protobuf schemas and generated packages are in a GPLv3 repository,
however, and the prose documentation does not fully specify every field and
state transition. Protocol facts and interoperable wire behavior are different
from copying an expressive schema or implementation, but the exact boundary is
a legal question. Before publishing a permissive crate:

1. ask Meshtastic to dual-license the wire schemas under a permissive license,
   or publish a separate permissive protocol specification;
2. otherwise have an unexposed implementation team work from public prose,
   independently recorded captures, and a separately written field registry;
3. have counsel review the provenance and distribution plan.

Upstream's own hardware registry is encouraging evidence, not a license grant.
It assigns `ROUTASTIC = 85` to software that "does not run Meshtastic's code"
but supports the same frame format. That demonstrates that an independent
compatible implementation is a recognized technical shape.

Use an independent project name. Meshtastic is a registered trademark and its
policy restricts third-party product names. Documentation can describe protocol
compatibility with clear non-endorsement language.

### Using GPL wire schemas without relicensing Retinue

Repository separation alone has no licensing effect. If GPL-generated schema
code and Retinue are linked into one firmware image, that distributed image is
a combined GPLv3 work. Rust features, static libraries, FFI, or putting the
crates in separate repositories do not change that practical result.

The clean dependency direction is downstream:

```text
MIT/Apache projects
  retinue-core       radio-core       Heltec BSPs
          \              |              /
           \             |             /
            GPLv3 retinue-meshtastic-firmware
                 + GPLv3 Meshtastic schemas
```

Retinue and the radio workspace remain MIT/Apache and do not depend on GPL code.
A separate GPLv3 firmware product depends on them and on the official
Meshtastic schemas. Apache-2.0 and MIT code can be incorporated into a GPLv3
work; the combined firmware and its Meshtastic glue are then distributed under
GPLv3 with corresponding source. This is coherent if a GPL combined image is
acceptable.

For a host-based system, the GPL component can instead be a sidecar:

```text
MIT/Apache Retinue <-> small framed packet socket <-> GPL Meshtastic adapter
                                                   official Rust client/schemas
```

The GNU GPL FAQ says pipes and sockets normally connect separate programs, while
also warning that sufficiently intimate exchange can still form one combined
program. Keep the boundary packet-oriented, independently useful, and
replaceable, then obtain legal review before distributing the pair. This route
preserves Retinue's license but preserves the external host too.

The only route to a hostless MIT/Apache Retinue-Meshtastic image is a permissive
wire contract: an upstream dual-license/specification grant or a defensible
independent implementation. A separately stored GPL schema crate cannot be
quietly pulled into the permissive firmware.

## RNode-compatible personality

This image remains a host-controlled data radio. Retinue or RNS elsewhere owns
identity, announces, links, routing, and resources. The firmware owns:

- USB CDC first, then BLE and optional TCP;
- KISS framing and the RNode control session;
- persisted frequency, bandwidth, spreading factor, coding rate, power, and
  regional limits;
- bounded flow control, readiness, reset, error, queue, RSSI/SNR, and statistics;
- SX1262 channel activity, airtime, scheduling, receive delivery, and the
  stock-compatible long-packet behavior needed by Reticulum's 500-byte MTU.

The public original-RNode command table establishes the legacy session shape,
but it is not a complete RNode 1.86 specification. Build a black-box host and
on-air capture corpus against pinned stock devices. Preserve exact captures and
the tests derived from them without copying firmware source.

### RNode done condition

- The same host conformance suite passes against pinned stock RNode and the Rust
  image without host-side exceptions.
- Stock and Rust devices exchange 500-byte packets in both directions across
  the selected modulation matrix.
- Invalid settings, full queues, busy timeout, reset, reconnect, duplicate
  frames, and interrupted transmissions have deterministic outcomes.
- Radio, power, airtime, flow-control, and queue policy are persisted settings
  with safe regional caps.

## Native Retinue personality

The independent radio crate does not by itself put Retinue on the board. Retinue
still needs an executor-neutral, bounded state machine:

```text
Node::ingest(interface, packet, now) -> bounded actions and events
Node::poll(now)                      -> bounded actions and next deadline

shell supplies: clock, entropy, persistence, radio, USB/BLE, and scheduling
```

Current Retinue still uses Tokio, `std`, unbounded channels, growable maps and
queues, and in-memory resource assembly in its live endpoint. A first embedded
profile must bound links, routes, queues, reliable-channel state, and resource
windows; inject entropy and time; and stream persistence. `no_std + alloc` is a
useful measurement spike, not the T114 release capacity contract.

The direct Retinue radio bearer can reuse the same independently specified
RNode-compatible modulation, channel-access, and long-packet work without
emulating the USB/KISS modem boundary.

### Retinue done condition

- `thumbv7em-none-eabihf` builds a `#![no_std]` T114 endpoint profile and an
  ESP32-S3 build proves the V4 shell.
- Linker receipts record flash, static RAM, heap high-water mark, and maximum
  task/future size.
- Full link, route, queue, and resource tables return typed capacity errors and
  remain live after rejection.
- The board announces, links, and exchanges reliable data directly with pinned
  RNS and Retinue peers after loss, reordering, and reboot.

## Meshtastic-compatible personality

This is a third protocol implementation, not a thin setting on the RNode image.
The minimum useful slice is:

1. regional LoRa presets, sync word, preamble, and the raw 16-byte packet header;
2. channel hash, AES-CTR channel payloads, and a small independent protobuf wire
   codec for the explicitly supported messages;
3. packet identity, duplicate suppression, CSMA/CA, managed flooding, hop limits,
   implicit broadcast ACKs, and direct ACK/retry;
4. NodeInfo and channel text traffic against stock nodes;
5. the documented streaming client API over USB, then BLE, so an official app
   can provision the node and exchange supported messages;
6. version 2.6 next-hop direct routing and current public-key direct messages
   after broadcast/channel interoperability is stable.

Do not claim full Meshtastic compatibility from successful LoRa frame exchange.
The app-facing NodeDB/configuration flow and the mesh's retry, deduplication,
routing, crypto, and airtime behavior are part of the product contract.

### Meshtastic done condition

- A stock node and the Rust node exchange broadcast text and NodeInfo in both
  directions through a two-hop stock relay.
- Stock nodes relay frames from the Rust node, and the Rust node relays stock
  traffic with bounded duplicate state and measured airtime.
- A pinned official phone or web client provisions the Rust node and observes
  supported traffic through the standard client API.
- Busy channel, duplicate, missing ACK, invalid ciphertext, unknown protobuf
  field, full NodeDB, reboot, and region-limit cases are deterministic.
- The release declares its exact compatibility baseline and unsupported
  messages instead of implying parity with all official modules.

## Retinue over the Meshtastic bearer

Once the Meshtastic personality exists, embedded Retinue can use it without a
Pi. The official port registry assigns `RETICULUM_TUNNEL_APP = 76` to fragmented
RNS packets. A combined firmware can fragment Reticulum's 500-byte packets,
submit them to the local Meshtastic mesh, reassemble them, and feed them directly
to the Retinue node state machine.

This is a compatibility mode, not the first embedded bearer. It runs two mesh
and reliability layers, loses the larger packet when a fragment is missing, and
needs memory for Meshtastic NodeDB/deduplication plus Retinue links/routes. Start
on V4. Measure it before deciding whether a bounded T114 profile is worthwhile.

The combined image done condition is exact 500-byte packet round trips over two
and three stock Meshtastic hops, bounded reassembly memory, deterministic loss
and duplicate behavior, and measured latency, goodput, retries, current, and
airtime beside ordinary text and telemetry traffic.

## Board order

1. **T114:** prove the common crate and separate RNode, Retinue-small, and
   Meshtastic-minimum images. Its nRF52840 has the strongest Embassy path and its
   256 KB RAM forces honest limits.
2. **V4:** prove native USB, flash, PSRAM, and its board-specific high-power RF
   path, then try the combined Retinue-over-Meshtastic image.
3. **V3:** add the conservative ESP32-S3 target after the shared contracts are
   stable, unless it is the board already available for the stock oracle.

## Ordered gates

1. Buy or select two boards and pin stock RNode and Meshtastic firmware versions.
2. Record a clean provenance policy before anyone implementing the permissive
   protocol crates studies GPL implementation source.
3. Land generic T114 USB, flash, entropy, SX1262 TX/RX, channel activity, bounded
   queues, settings, and power receipts.
4. Capture stock RNode host sessions and on-air 500-byte exchanges; pass the
   independent RNode personality against those fixtures.
5. Capture documented Meshtastic broadcast text and NodeInfo exchanges; pass the
   minimum independent personality against stock nodes and an official client.
6. Extract Retinue's bounded `no_std` node and pass direct on-air link tests.
7. On V4, compose the Meshtastic bearer with embedded Retinue on port 76 and
   measure whether the double stack is useful.

## Sources checked 2026-07-19

- [Original RNode USB and serial command table](https://unsigned.io/hardware/Original_RNode.html)
- [RNode Firmware boards and GPLv3 boundary](https://github.com/markqvist/RNode_Firmware)
- [Reticulum interface manual](https://reticulum.network/manual/interfaces.html)
  and [500-byte MTU reference](https://reticulum.network/manual/reference.html)
- [Heltec WiFi LoRa 32 V3/V4 comparison](https://docs.heltec.org/en/node/esp32/wifi_lora_32/index.html)
  and [T114 documentation](https://docs.heltec.org/zh_CN/node/nrf/mesh_node_t114/index.html)
- [Nordic nRF52840 specifications](https://www.nordicsemi.com/products/nrf52840)
- [Embassy](https://github.com/embassy-rs/embassy),
  [`esp-hal`](https://github.com/esp-rs/esp-hal), and
  [`lora-phy`](https://docs.rs/lora-phy/latest/lora_phy/)
- [Meshtastic mesh algorithm and on-air framing](https://meshtastic.org/docs/overview/mesh-algo/),
  [encryption](https://meshtastic.org/docs/overview/encryption/), and
  [client API](https://meshtastic.org/docs/development/device/client-api/)
- [Official Meshtastic protobuf repository and license](https://github.com/meshtastic/protobufs),
  [`ROUTASTIC` compatibility marker](https://github.com/meshtastic/protobufs/blob/master/meshtastic/mesh.proto),
  and [`RETICULUM_TUNNEL_APP`](https://github.com/meshtastic/protobufs/blob/master/meshtastic/portnums.proto)
- [Meshtastic trademark policy](https://meshtastic.org/docs/legal/licensing-and-trademark/)
- [Official Meshtastic Rust desktop client](https://github.com/meshtastic/rust)
- [MeshCore embedded library, KISS modem, and MIT license](https://github.com/meshcore-dev/MeshCore)
- [GNU GPL FAQ on linking, aggregation, pipes, and sockets](https://www.gnu.org/licenses/gpl-faq.en.html)
  and [Apache-2.0/GPLv3 one-way compatibility](https://www.apache.org/licenses/GPL-compatibility)
