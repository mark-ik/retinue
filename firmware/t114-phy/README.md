# T114 direct PHY

Independent Embassy firmware for the Heltec T114's nRF52840 and SX1262. Pin
assignments come from Zephyr's Apache-2.0 T114 board definition. The radio uses
Meshtastic LongFast modulation at 906.875 MHz, 17 dBm, and the documented sync
word `0x2B` (`0x24B4` in the SX1262 registers).

The USB CDC protocol carries opaque radio packets and a runtime radio profile:

- host transmit: `01 <length:u16-le> <packet>`
- radio receive: `81 <length:u16-le> <rssi:i16-le> <snr:i16-le> <packet>`
- transmit result: `82 <result:u8> <length:u16-le>` where result zero is success
- host configure: `02 <frequency:u32-le> <bandwidth:u32-le> <sf:u8> <cr-denominator:u8> <preamble:u16-le> <sync:u8> <flags:u8> <power:i8>`
- configure result: `83 <result:u8>` where result zero is success

CDC transfers may split a frame at any byte. The firmware accumulates transmit
commands and chunks receive events into 64-byte USB packets. `status\n` and
`sync\n` remain available as human-readable probes.

Build and package for both supported bootloader paths:

```text
cargo build -p tulle-t114-phy --release --target thumbv7em-none-eabihf
cargo objcopy -p tulle-t114-phy --release --target thumbv7em-none-eabihf -- -O binary firmware/t114-phy/tulle-t114-phy-v5.bin
adafruit-nrfutil dfu genpkg --dev-type 0x52 --application firmware/t114-phy/tulle-t114-phy-v5.bin --application-version 5 --sd-req 0xFFFE firmware/t114-phy/tulle-t114-phy-v5.zip
python path/to/uf2conv.py -c -b 0x26000 -f 0xADA52840 -o firmware/t114-phy/tulle-t114-phy-v5.uf2 firmware/t114-phy/tulle-t114-phy-v5.bin
```

The Heltec bootloader's documented path is to double-press reset and copy the
UF2 onto the `HT-n5262` drive. Serial DFU also accepts the ZIP. The application
address is `0x26000` for the board's S140 v6 bootloader. The same SoftDevice
layout reserves RAM below `0x20006000`; the linker script keeps Embassy state
above that boundary.

Board acceptance is complete when the application enumerates as USB VID/PID
`1915:521f`, `status` reports the SX1262 online, a stock LongFast node's frame is
received byte-exactly, and a raw Sennet packet transmitted here is accepted by
that node.
