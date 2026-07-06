# retinue

An endpoint-scoped Rust implementation of the
[Reticulum](https://reticulum.network/) protocol: identity, announces, links,
and resources, built for embedding as a library. Transport-node routing is a
non-goal; a retinue accompanies a peer, it does not carry other people's
traffic.

**Status: name reservation + scaffold.** Nothing here works yet. The plan lives
in [`design_docs/`](design_docs/).

## Posture

- Wire-compatibility target: RNS 1.3.x.
- Implemented from the public-domain Reticulum protocol specification and
  manual; validated against the Python reference implementation as a black-box
  interoperability oracle (mixed-runtime smoke tests), not by reading its code.
- Not the reference implementation, and not affiliated with the Reticulum
  project.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same terms.
