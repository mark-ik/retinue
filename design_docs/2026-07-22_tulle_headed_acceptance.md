# Retinue over Tulle headed acceptance

**Date:** 2026-07-22  
**Result:** passed

## Bench

- COM6: Heltec WiFi LoRa 32 v4, RNode firmware 1.86
- COM5: Heltec T114, RNode firmware 1.86
- 915 MHz, BW 125 kHz, SF8, CR 4/5, 7 dBm
- Retinue link MTU 255
- reliable maximum window 1
- Resource request window 1

COM4 became COM5 when the T114 changed from its previous application USB PID to
the RNode firmware PID. Port numbers are not stable board identities.

## Command

```text
cargo run --features tulle-radio --example tulle_headed -- COM6 COM5
```

## Receipt

The v4 initiated both bulk transfers and the T114 accepted them:

```text
radios online: COM6=Some((1, 86)), COM5=Some((1, 86))
discovery: reliable destination announced over RF
reliable: 2048-byte request and receipt passed
discovery: resource destination announced over RF
resource: 4096-byte publish/fetch passed
RETINUE TULLE HEADED PASSED
```

The acceptance covers announce discovery, authenticated link setup, IDENTIFY,
Channel/Buffer proofs and retransmission, half-close and reply, Resource
advertisement, bounded part requests, hashmap update, reassembly, and proof.
Both application payloads were checked byte-exactly.

## Findings paid into the implementation

1. Link requests retry on a caller-set interval. A repeated request receives the
   cached proof and does not create a second accepted stream.
2. The reliable dynamic window has a caller-set ceiling. A ceiling of one avoids
   data/proof collisions on strict half-duplex media.
3. The endpoint's caller-set link MTU controls reliable chunk size and Resource
   part size. Resource advertisement and HMU hash windows are also bounded to it.
4. Resource advertisement retries stop after the first valid request. The
   receiver does not reset progress on a repeated advertisement.
5. The Resource request window is a setting. One part per request made the RF
   exchange converge without opposing bursts.

The reverse bulk direction, T114 transmitting to v4, was inconsistent on this
bench: short frames crossed, but repeated 243-byte frames sometimes stopped
arriving. The passing receipt therefore proves the protocol and pump path with
the v4 as bulk sender, not symmetric T114 bulk throughput.
