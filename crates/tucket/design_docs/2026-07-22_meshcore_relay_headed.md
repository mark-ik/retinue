# MeshCore relay headed acceptance

On 2026-07-22, Tucket passed a real one-hop source-route exchange across three
radios:

- COM6: Heltec WiFi LoRa 32 v4 running Tulle direct-PHY
- COM8: Heltec WiFi LoRa 32 v4 running official MeshCore companion v1.15.0,
  companion protocol 11
- COM9: Heltec T114 running official MeshCore repeater v1.16.0

The T114 had been COM5 while running RNode. It re-enumerated as COM9 with USB
VID/PID `239A:8029` after the repeater flash. Its configuration was:

```text
name: TucketRelay
public key: A1B00F396111474BD3FB375EFA771AC26DC3B200C29C090B6F9DF1ECDD0C2A8B
radio: 915.0,250,10,5
repeat: on
path.hash.mode: 0
```

The repeater image was the official
`Heltec_t114_repeater-v1.16.0-07a3ca9.zip`, SHA-256
`c11c33b4480ded01f30cbaaa38e490c56dcace2b15c412839eaf3b9759c17a3b`.
MeshCore publishes its firmware through the
[official flasher and releases](https://github.com/meshcore-dev/MeshCore#-meshcore-flasher)
and documents the
[repeater serial settings](https://docs.meshcore.io/cli_commands/).

## Gate

The command was:

```text
cargo run --features hardware --example meshcore_headed -- COM6 COM8 915000000 a1
```

The optional `a1` argument installs the repeater's one-byte hash as the route
on both endpoints. A direct packet with path `[a1]` is not addressed to either
endpoint on its first transmission. Only the T114 can consume that first hop
and retransmit the packet with a zero-hop path. This prevents close physical
placement from turning direct endpoint reception into a false pass.

Observed output:

```text
radios online: COM6=Tulle direct PHY, COM8=MeshCore companion protocol 11
authenticated adverts crossed the MeshCore/Tucket boundary
forced reciprocal one-hop route through relay a1
Tucket text and MeshCore ACK crossed the relay
MeshCore text and Tucket ACK crossed the relay
TUCKET MESHCORE RELAY HEADED PASSED
```

This proves Tucket-origin encrypted text, stock-origin encrypted text, and
acknowledgements in both directions through an unmodified MeshCore repeater.
It does not measure range, loss recovery, or multi-hop route discovery.
