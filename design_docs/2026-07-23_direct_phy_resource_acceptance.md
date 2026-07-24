# Retinue Resource over Tulle direct PHY

**Date:** 2026-07-23

**Result:** passed

## Bench

- COM6: Heltec WiFi LoRa 32 v4 running Tulle direct-PHY firmware
- COM10: Heltec T114 running Tulle direct-PHY firmware v10
- 906.875 MHz, BW 250 kHz, SF8, CR 4/5, 17 dBm
- sync word `0x12`, preamble 16, explicit header, CRC enabled
- Retinue link MTU 255
- Resource request window 1

The T114 application enumerated as USB VID/PID `1915:521f`. Tulle configured
both radio profiles at startup through the shared direct-PHY USB protocol.

## Command

```text
cargo run --features tulle-radio --example direct_phy_resource -- COM6 COM10 4096
```

## Receipt

```text
radios online: COM6=client, COM10=server
discovery: resource destination announced over direct PHY
publish: client to server 4096 bytes passed
fetch: server to client 4096 bytes passed
RETINUE DIRECT-PHY RESOURCE HEADED PASSED
```

The first link exercised `Endpoint::publish_resource_with_config` at COM6 and
an accepted `ResourceSession::fetch` at COM10. The second link exercised the
complementary wrappers: `Endpoint::fetch_resource_with_config` at COM6 and an
accepted `ResourceSession::publish` at COM10. Both application payloads were
checked byte-exactly.

This closes the direct-PHY portability gate for Retinue Resource sessions and
provides a second protocol consumer for Tulle's `PacketRadio` implementation
after Sennet. It proves direct, one-hop transfer on this bench. It does not
claim range, routed forwarding, or loss recovery over RF.
