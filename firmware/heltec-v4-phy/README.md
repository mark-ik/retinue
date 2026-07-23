# Heltec WiFi LoRa 32 v4 direct PHY

Direct SX1262 firmware for the ESP32-S3 Heltec WiFi LoRa 32 v4. The radio pin
mapping is taken from Heltec's published v4.2 schematic:
<https://resource.heltec.cn/download/WiFi_LoRa_32_V4/Schematic/WiFi_LoRa_32_V4.2.pdf>.

The firmware uses the same USB framing and LongFast profile documented by the
T114 target. Build it with the Espressif Rust toolchain:

```text
. $HOME/export-esp.ps1
cargo +esp build -p tulle-heltec-v4-phy --release --target xtensa-esp32s3-none-elf -Zbuild-std=core
```

Hardware acceptance passed on 2026-07-22 at 906.875 MHz against a stock
LongFast node. The firmware received a 49-byte stock frame and transmitted a
47-byte Sennet transport frame which the stock node decrypted and delivered to
its client stream.
