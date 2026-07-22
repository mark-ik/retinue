# First reliable link over real RF: results and findings

**Date:** 2026-07-21, the evening the boards arrived.
**Status:** Milestone achieved + engineering findings for the Tulle integration.

## What ran

Two retinue endpoints, one per physical RNode (Heltec T114 `c2:c7:3c` and Heltec
V4 `c3:c8:3f`, RNode firmware 1.86), bridged through tulle's sans-io `RNode`
modem over serial, 915 MHz, BW 125k, SF8, CR5, 7 dBm, same desk. The harness
(scratchpad, path-deps, deliberately uncommitted) pumps each radio to a
`retinue::endpoint::Interface`.

Sequence, all over the air: the server registers a reliable destination and
announces; the client hears the announce (RSSI −20 dBm, SNR ~13 dB), opens a
reliable link (**established in 0.9 s**: request 86 B out, proof 118 B back);
the client IDENTIFYs, streams a 49-byte message through the Channel/Buffer
path with link-proof acks, half-closes; the server reads it intact, replies,
closes. Request and reply both verified byte-exact.

Earlier the same evening, the announce-only milestone: a 180-byte announce
crossed RF and validated end to end (destination hash matched byte-exact).

## Findings (the real payload)

1. **The reliable driver's retransmit clock is medium-blind.** `RELIABLE_TICK_MS
   = 50` with the Buffer's tick-counted retransmit timeout was tuned for local
   pipes. Over LoRa a data->proof round trip is ~1-2 s (each frame 250-450 ms of
   airtime, half-duplex turnaround between), so the driver retransmits several
   times before the first proof can possibly return. The exchange still
   converges (43 TX frames for what needs ~12), but the waste is systematic.
   Fix direction: the Buffer already measures EWMA RTT for window sizing; the
   retransmit timeout should key off that same measured RTT (plus dispersion),
   not a fixed tick count. Alternatively or additionally, the endpoint should
   let an interface declare its expected RTT scale so the driver starts sane.
2. **The pump must pace transmissions by airtime.** Feeding the radio at queue
   speed bloats the modem's TX queue (each queued frame adds its full airtime
   of latency) and starves half-duplex RX windows; the first run turned this
   into a visible retransmit storm. One frame per `enqueue()`-returned airtime
   plus ~180 ms turnaround kept the channel breathing and the run converged
   cleanly. This pacing belongs in tulle's pump layer, next to the
   `AirtimeBudget` gate, when the real (non-scratchpad) pump is built.
3. **Serial line-control gotchas, now paid for:**
   - nRF/CDC devices gate output on DTR. pyserial asserts it on open; Rust
     serial crates do not. Without `set_dtr(true)` the device is silent.
   - Do NOT assert RTS on ESP32 boards: RTS drives the reset/boot circuit and
     an unclean process exit mid-session wedged the V4 into download mode
     (recovered by physical RST). DTR-only is sufficient and safe on both
     families.
   - COM port numbers are unstable across resets/reflashes on Windows; identify
     radios by USB VID (239A = nRF/T114, 303A = ESP32/V4), never by number.
4. **RNode provisioning after a broken autoinstall** (nRF port-renumber breaks
   the installer's flash-then-reopen): `rnodeconf -r --platform NRF52 --product
   c2 --model c7 --hwrev 1`, then `-H <sha256 of the .bin>` — the application
   image hash, not the release zip hash. A wrong hash shows "firmware corrupt"
   on-device and locks the radio off (`RADIO_STATE` echo stays 0); reboot after
   correcting.

## What this proves

The sans-io discipline paid out in full: the reliable machinery that was
loss-tested on virtual clocks ran unmodified over real radio, and every
desk-truth surprise (retransmit tuning, pacing, line control) landed in the
pump and configuration layer, not in the protocol code. Tulle's `RNode` was
gold-tested against captured fixtures and then drove live hardware the same
day with one added line (DTR).

## Follow-ons

- retinue: RTT-adaptive retransmit timeout for the reliable driver (finding 1).
- tulle: the real pump (serial transport + pacing + `AirtimeBudget`), promoting
  the scratchpad harness pattern into `tulle` behind a feature, with retinue
  attached via the `Interface` seam.
- The link-request path over an interface with a transport node between the
  radios (multi-hop over RF) once a third radio exists.
