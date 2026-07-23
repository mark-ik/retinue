# tulle

The shared radio interface layer for LoRa mesh stacks: serial modem control
(RNode/KISS style framing) and medium access (listen-before-talk, duty-cycle
accounting), beneath [retinue](https://github.com/mark-ik/retinue) and its
mesh interop siblings, [tucket](https://github.com/mark-ik/tucket) and
[sennet](https://github.com/mark-ik/sennet).

A tulle is a fine net fabric: the material every protocol is woven across.

**Status:** the shared airtime gate and sans-I/O RNode driver are live. The optional
`serial-async` feature adds the real Tokio serial pump with DTR/RTS discipline,
initialisation retry, airtime pacing, and bounded frame queues.

The same feature now exposes `DirectPhySerialLink`, the reusable host wrapper
for Tulle's USB direct-PHY firmware. It handles split USB events, bounded queues,
transmit acknowledgements, RSSI/SNR delivery, and the shared airtime budget.

The workspace also contains direct-PHY Embassy firmware for the Heltec WiFi
LoRa 32 v4 and T114, plus a reusable `tulle-phy-profile` crate. Both targets
program the documented `0x2B` sync word directly as SX1262 registers `0x24B4`
and expose binary USB commands for raw packet transmit and receive with
RSSI/SNR. The v4 target has passed bidirectional LongFast acceptance against a
stock node: raw receive was byte-exact, and the stock node accepted a packet
transmitted through Tulle. The T114 accepted its DFU package on 2026-07-22 but
did not enumerate the application USB device, so board startup remains a live
firmware defect.

Run the two-board hardware acceptance with:

```text
cargo run --features serial-async --example rnode_roundtrip -- COM5 COM6
```

The T114 DFU package is produced at
`firmware/t114-phy/tulle-t114-phy-v3.zip`.

Build and flash the v4 target with:

```text
. $HOME/export-esp.ps1
cargo +esp build -p tulle-heltec-v4-phy --release --target xtensa-esp32s3-none-elf -Zbuild-std=core
espflash flash --port COM6 --chip esp32s3 C:\t\graphshell-target\xtensa-esp32s3-none-elf\release\tulle-heltec-v4-phy
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
