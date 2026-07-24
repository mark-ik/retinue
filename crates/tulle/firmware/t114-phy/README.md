# T114 direct PHY

Independent Embassy firmware for the Heltec T114's nRF52840 and SX1262. Pin
assignments and the DIO2 antenna-switch and DIO3 TCXO wiring come from Heltec's
published [Rev. 2.1 schematic](https://resource.heltec.cn/download/Mesh_Node_T114/schematic/MeshNode-T114_V2.1.pdf).
The radio uses Meshtastic LongFast modulation at 906.875 MHz, 17 dBm, and the
documented sync word `0x2B` (`0x24B4` in the SX1262 registers).

The SX1262 uses a software mode-0 SPI bus on the schematic pins. The original
SPIM3 integration accepted commands but read the sync-word registers as
`0x0000` and never asserted TX-done. The software bus reads back `0x24B4` and
has passed RF acceptance in both directions.

The USB CDC protocol carries opaque radio packets and a runtime radio profile:

- host transmit: `01 <length:u16-le> <packet>`
- radio receive: `81 <length:u16-le> <rssi:i16-le> <snr:i16-le> <packet>`
- transmit result: `82 <result:u8> <length:u16-le>` where result zero is success
- host configure: `02 <frequency:u32-le> <bandwidth:u32-le> <sf:u8> <cr-denominator:u8> <preamble:u16-le> <sync:u8> <flags:u8> <power:i8>`
- configure result: `83 <result:u8>` where result zero is success
- SX1262 diagnostic: `84 <irq:u16-le> <errors:u16-le> <sync-msb:u8> <sync-lsb:u8>`

CDC transfers may split a frame at any byte. The firmware accumulates transmit
commands and chunks receive events into 64-byte USB packets. `status\n` and
`sync\n` remain available as human-readable probes. `radio\n` emits the binary
diagnostic event. `bootloader\n` enters the board's serial-only DFU mode without
a physical double-reset.

Build and package for both supported bootloader paths:

```text
cargo build -p tulle-t114-phy --release --target thumbv7em-none-eabihf
cargo objcopy -p tulle-t114-phy --release --target thumbv7em-none-eabihf -- -O binary firmware/t114-phy/tulle-t114-phy-v10.bin
adafruit-nrfutil dfu genpkg --dev-type 0x52 --application firmware/t114-phy/tulle-t114-phy-v10.bin --application-version 10 --sd-req 0xFFFE firmware/t114-phy/tulle-t114-phy-v10.zip
python path/to/uf2conv.py -c -b 0x26000 -f 0xADA52840 -o firmware/t114-phy/tulle-t114-phy-v10.uf2 firmware/t114-phy/tulle-t114-phy-v10.bin
```

The Heltec bootloader's documented path is to double-press reset and copy the
UF2 onto the `HT-n5262` drive. Serial DFU also accepts the ZIP. The application
address is `0x26000` for the board's S140 v6 bootloader. The same SoftDevice
layout reserves RAM below `0x20006000`; the linker script keeps Embassy state
above that boundary.

On 2026-07-23 the application enumerated as USB VID/PID `1915:521f` on COM10
and read back sync registers `0x24B4`. A headed Sennet receipt against the
Heltec v4 direct-PHY target on COM6 passed encrypted text in both directions:
T114 to v4 at -14 dBm / 6.0 dB SNR, then v4 to T114 at -84 dBm / 5.0 dB SNR.
