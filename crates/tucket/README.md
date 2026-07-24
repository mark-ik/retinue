# tucket

MeshCore interop for the [retinue](https://github.com/mark-ik/retinue) radio
family: node management and text interop with MeshCore mesh networks, on the
shared [tulle](https://github.com/mark-ik/tulle) radio layer.

A tucket is a trumpet flourish announcing a single arrival.

**Status:** authenticated adverts, flood text and acknowledgements, forwarding,
and reciprocal direct-path learning are implemented. A successful flooded
exchange teaches both endpoints a route; later text and acknowledgements select
the learned hop path. Private text sends now expose a caller-timed retry state:
attempt numbers are authenticated, delayed acknowledgements remain valid, and
the default fourth transmission clears a failed direct path and floods to learn
a replacement. Attempt count and flood fallback are settings. The in-memory
three-node acceptance covers discovery, reply, direct delivery, and fallback
through a repeater.

The headed acceptance passes against the official MeshCore companion v1.15.0
firmware on a Heltec WiFi LoRa 32 v4. Current structured chat adverts were
imported and exchanged over RF; a stock-origin flood established reciprocal
paths, then Tucket and stock MeshCore each selected that direct route for text
and received the other's acknowledgement.

A second headed acceptance passes through an official MeshCore repeater v1.16.0
on a Heltec T114. Tucket and the stock companion were each given the repeater's
one-hop source route. Encrypted text and acknowledgements crossed the named
relay in both directions. The hardware receipt is in
[`design_docs/2026-07-22_meshcore_relay_headed.md`](design_docs/2026-07-22_meshcore_relay_headed.md).

With the `hardware` feature, `meshcore_headed` configures an official MeshCore
companion through its serial API while Tucket uses Tulle direct-PHY on the
other radio. The acceptance requires authenticated adverts and encrypted text
in both directions, then checks that both implementations select the reciprocal
direct route and acknowledge it over RF.

An optional fourth argument is a repeater's one-byte hash in hexadecimal:

```text
cargo run --features hardware --example meshcore_headed -- COM6 COM8 915000000 ab
```

In that mode the harness installs the same one-hop source route on Tucket and
the stock companion. Each endpoint ignores the other's original RF
transmission because the repeater is the named next hop. The acceptance passes
only after encrypted text and its acknowledgement cross that repeater in both
directions.

## License

Licensed under the Mozilla Public License, Version 2.0 ([LICENSE](LICENSE)).

MPL-2.0 is file-level copyleft: you may use this crate in a larger work under
any license, including a proprietary one, but modifications to *these files*
must be published under the MPL. It is GPL-compatible, so it combines into the
GPLv3 firmware images this project ships.

Portions were ported from the upstream [MeshCore](https://github.com/ripplebiz/MeshCore)
project, which is MIT licensed. MIT permits relicensing a derivative work and
requires the original notice be retained; it is reproduced in [NOTICE](NOTICE)
and applies to those portions.
