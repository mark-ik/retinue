# tulle

The shared radio interface layer for LoRa mesh stacks: serial modem control
(RNode/KISS style framing) and medium access (listen-before-talk, duty-cycle
accounting), beneath [retinue](https://github.com/mark-ik/retinue) and its
mesh interop siblings, [tucket](https://github.com/mark-ik/retinue) and
[sennet](https://github.com/mark-ik/retinue).

A tulle is a fine net fabric: the material every protocol is woven across.

**Status:** the shared airtime gate and sans-I/O RNode driver are live. The optional
`serial-async` feature adds the real Tokio serial pump with DTR/RTS discipline,
initialisation retry, airtime pacing, and bounded frame queues.

The same feature now exposes `DirectPhySerialLink`, the reusable host wrapper
for Tulle's USB direct-PHY firmware. It handles split USB events, bounded queues,
transmit acknowledgements, RSSI/SNR delivery, and the shared airtime budget.

The workspace also contains direct-PHY Embassy firmware for the Heltec WiFi
LoRa 32 v4 and T114, plus a reusable `selvage` crate. Both targets
program the documented `0x2B` sync word directly as SX1262 registers `0x24B4`
and expose binary USB commands for raw packet transmit and receive with
RSSI/SNR. The v4 target has passed bidirectional LongFast acceptance against a
stock node: raw receive was byte-exact, and the stock node accepted a packet
transmitted through Tulle. The T114 now enumerates and has passed bidirectional
Sennet LongFast text acceptance against the v4 direct-PHY target. Its SX1262
bus uses software mode-0 SPI: SPIM3 produced a false-online state with zeroed
sync-word readback on the board, while the software bus read back `0x24B4` and
completed both RF directions.

Run the two-board hardware acceptance with:

```text
cargo run --features serial-async --example rnode_roundtrip -- COM5 COM6
```

The accepted T114 DFU package is produced at
`firmware/t114-phy/tulle-t114-phy-v10.zip`.

Build and flash the v4 target with:

```text
. $HOME/export-esp.ps1
cargo +esp build -p tulle-heltec-v4-phy --release --target xtensa-esp32s3-none-elf -Zbuild-std=core
espflash flash --port COM6 --chip esp32s3 C:\t\graphshell-target\xtensa-esp32s3-none-elf\release\tulle-heltec-v4-phy
```

## License

Licensed under the Mozilla Public License, Version 2.0 ([LICENSE](LICENSE)).

MPL-2.0 is file-level copyleft: you may use this crate in a larger work under
any license, including a proprietary one, but modifications to *these files*
must be published under the MPL. It is GPL-compatible, so it combines into the
GPLv3 firmware images this project ships.
