# Retinue — the radio family

One workspace for the Merely radio stack: mesh protocols, the shared radio
interface layer, and the firmware that runs on real hardware. Each crate keeps
its own README; this file is the map.

## Crates

| Crate | What it is |
|---|---|
| [`retinue`](crates/retinue) | A Rust implementation of the Reticulum protocol: identity, announces, links, resources, and routing. The protocol is public domain; this is not the reference implementation ([reticulum.network](https://reticulum.network)). |
| [`tulle`](crates/tulle) | Shared radio interface layer for LoRa mesh stacks: serial modem control, direct PHY, and medium access. |
| [`tulle-phy-profile`](crates/phy-profile) | The PHY parameter profile shared by the host stacks and the firmware. |
| [`sennet`](crates/sennet) | Independent, permissively licensed mesh radio protocol implementation, Meshtastic-compatible on the wire. |
| [`tucket`](crates/tucket) | MeshCore interop: node management, routing, and text interop over LoRa mesh. |

## Firmware

`firmware/` holds the embedded targets, which are workspace members but not
default members — build them by name:

```sh
cargo build -p tulle-t114-phy --release --target thumbv7em-none-eabihf
```

`vendor/lora-phy` is a vendored fork of the `lora-phy` driver and keeps its own
MIT/Apache-2.0 licensing.

## License

Mozilla Public License 2.0 ([LICENSE](LICENSE)), except where a subdirectory
states otherwise. MPL-2.0 is file-level copyleft: these crates may be used in a
larger work under any license, including a proprietary one, but modifications
to *these files* must be published under the MPL.

`crates/tucket/NOTICE` records the MIT-licensed MeshCore portions it derives
from, and `crates/sennet/PROVENANCE.md` records how that implementation was
built.

## History

`tulle`, `sennet`, and `tucket` were merged into this workspace on 2026-07-23,
with their histories preserved. Their standalone repositories are archived.
