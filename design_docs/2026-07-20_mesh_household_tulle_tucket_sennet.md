# The mesh household: Tulle, Tucket, Sennet

**Date:** 2026-07-20
**Status:** Decided (names, crate topology, layering rules). No code exists yet for
any of the three crates; this doc records the decisions that will shape them.
**Siblings:** `2026-07-19_modem_embedded_and_meshtastic_research.md` (embedded
prospects, GPL boundary, Meshtastic feasibility),
`2026-07-19_heltec_rnode_and_embedded_rust.md` (hardware).

## Summary

retinue grows a family of sibling crates for radio hardware and foreign-mesh
interop. Names are decided and verified free on crates.io (2026-07-20):

| Name | Role | Provenance discipline |
|---|---|---|
| **retinue** | Reticulum implementation (exists) | black-box oracle vs RNS; never read RNS source |
| **Tulle** | shared radio/interface layer beneath retinue and both mesh crates | clean; RNode wire captured from hardware, not from GPL firmware source |
| **Tucket** | MeshCore interop crate | MeshCore is MIT: read the source, port directly |
| **Sennet** | independent Meshtastic-compatible implementation | clean-room: never read the GPLv3 schemas; wire captures + public docs only |

The umbrella trait that lets merecat drive both mesh personalities is
deliberately unnamed for now (bench: `reticella`, which shares Reticulum's Latin
root *rete*, "net"; also `comitatus`).

Name logic, so nobody has to memorize it: the household well is retinue's own
(medieval court, trumpet signals). Tulle is a net fabric, the material every
protocol is woven across. A tucket is the flourish announcing a single arrival,
matching MeshCore's lean, individual character. A sennet is the ceremonial
fanfare for a procession of many, matching Meshtastic's managed-flooding crowd.
Sennet is also trademark-safe: "Meshtastic" is an enforced trademark, so the
independent project needs an independent name and non-endorsement language
("compatible with Meshtastic networks").

## Crate topology: separate crates, separate repos

Tucket and Sennet are siblings on top of Tulle, never one combined mesh crate,
and never folded into retinue. Three reasons, in order of weight:

1. **Provenance auditability.** Tucket's history may freely reference MeshCore
   source (MIT). Sennet's history must demonstrably never have touched the GPL
   schemas, the same way retinue's credibility rests on never reading RNS's
   Python. One shared history would force a reviewer to trust that both regimes
   stayed disciplined inside it. Two repos means two independently clean
   stories. A pristine, isolated history is itself the legal artifact.
2. **They share almost no code.** Different wire formats, crypto, routing, and
   app layers. What they share is the radio, and that is already Tulle.
3. **Different velocity.** Meshtastic churns its schemas release to release and
   carries the legal and maintenance load; MeshCore is small, stable, MIT. A
   consumer should be able to pull MeshCore support without dragging in the
   Meshtastic codec's clean-room maintenance burden.

Unification for merecat happens at a trait (the genet-probe Driveable seam
pattern), not by merging implementations. The trait covers drive/manage/IO
only: send a frame, receive a frame, node status. If routing logic leaks into
the trait, the abstraction is wrong.

## Layering: where routing lives

"Routing" is a stack of three tiers, and only the top one is per-protocol.

**Tier 1, medium access: lives in Tulle.** Listen-before-talk, channel activity
detection, backoff, duty-cycle accounting. This is arbitration of the shared
airwaves and needs no frame parsing: it operates on "N bytes at this spreading
factor, is the channel clear, am I within budget." Putting it in Tulle gives
one duty-cycle gate that all traffic passes through, native Reticulum and
mesh-bearer alike, which is what makes the good-citizenship rule (below)
enforceable in one place. Note this tier does not exist anywhere yet: retinue
has been host-side over TCP, so airtime arrives for the first time with Tulle
and the RNode work. This is a decision about where it lands, not a refactor.

**Tier 2, generic mechanisms: a shared utility crate or module, above Tulle.**
Bounded TTL dedup cache ("have I seen this frame"), hop-decrement-and-drop,
last-seen neighbor table shapes. Identical data structures across all three
protocols, but they cannot sink into Tulle because dedup must know a frame's
identity, which is protocol-specific parsing, and Tulle handles opaque bytes
only.

**Tier 3, the forwarding decision: irreducibly per-protocol.** Given a frame:
consume, drop, or forward, and by what rule. Reticulum looks up a destination
hash in a path table learned from announces (this already exists in retinue's
`endpoint.rs`: path table, `route_to`, `learn_path`, announce budget).
Meshtastic rebroadcasts within a hop limit. MeshCore does path discovery with
flood fallback. These decision procedures plus their addressing models are the
substance of each protocol; a shared router would be a lossy superset all three
fight. Tier 3 is most of what "they share almost no code" means.

## Additional capability: Reticulum over the meshes as bearer

Beyond the peer stacks, Tucket and Sennet can each expose a retinue `Interface`
implementation (sibling of the TCP and RNode interfaces) that carries opaque
Reticulum frames over the mesh as a transport medium. Reticulum is
bearer-agnostic by design, so this is architecturally native, and it is
technically cheap: it needs the mesh framing, channel crypto, and a small
envelope, not the application schemas, so it mostly sidesteps the GPL surface
that makes Sennet's peer stack the careful one. Expect a fragmentation layer:
roughly 200 usable bytes per mesh frame vs Reticulum's ~500-byte MTU.

**Legitimacy gate:** injecting undecodable frames onto a mesh you do not
participate in is parasitic. Foreign nodes flood-relay off the clear header and
spend their duty cycle carrying traffic they can never read. The rule is
therefore that the bearer interface rides *through* the participant stack: a
real, traffic-relaying mesh node that pulls its weight on the mesh it uses.
Interop first, bearer second; being a good mesh citizen is what makes the
bearer honest. Among our own nodes, native Reticulum over LoRa (Tulle/RNode) is
simpler than tunneling; the bearer earns its keep bridging into existing meshes
we also serve.

The bearer stacks two independent routers by design: the mesh floods the frame
hop by hop in its own terms while retinue's Transport does destination routing
end to end on top. Neither collapses into the other.

## What each mesh crate is for (scope discipline)

The value of mesh interop is social, not architectural: retinue already covers
every transport shape (packets, links, resources, LXMF), so Meshtastic and
MeshCore add install base and a management surface, never capability. Scope
accordingly:

- **Tucket and Sennet v1 scope:** management and text interop. Text messages,
  NodeInfo, position, admin. Not full feature parity, which for Sennet is a
  moving GPL-adjacent target and the strongest argument for staying minimal.
- **Sennet clean-room recipe:** transport/framing layer is fact-shaped, capture
  and reimplement without hesitation. The app-schema layer gets a hand-rolled
  codec for exactly the supported messages, written from wire captures and
  public prose, never from the `.proto` files and never via `protoc` on them.
  Counsel reviews the schema-reconstruction provenance before permissive
  publication. Asking upstream to dual-license the schemas is a cheap parallel
  move that would dissolve the whole hazard.
- **Personality flipping:** one radio speaks one protocol at a time. ESP32-S3
  boards (Heltec V4, 8MB flash, A/B partitions) can hold dual personalities and
  flip remotely; nRF52840 (T114, 1MB flash) flips by local reflash only. The
  switch command must arrive over a channel that survives the switch.

## Sequencing

None of this is on the critical path for the first sellable unit, which remains
stock certified hardware plus retinue-over-RNode managed through merecat. The
household's natural order once it starts: Tulle first (retinue needs it for
RNode regardless of the meshes), then Tucket (MIT, cheap, proves the
manage-foreign-meshes story), then Sennet (heaviest, clean-room), then the
bearer interfaces (gated on interop per the legitimacy rule).

## Licensing posture (RULED 2026-07-20, evening round)

Considered and decided after reviewing the GPLv3 vibe of comparable projects
(embedded Reticulum efforts, Sideband/NomadNet/RNode all GPL at the app or
firmware layer):

1. **All four crates stay MIT OR Apache-2.0.** MPL-2.0 for retinue/tulle was
   evaluated (file-level share-alike, static-link clean, would keep the
   implementation uncapturable) and declined for consistency: tucket must match
   MIT upstream and sennet's reason to exist is being the permissive
   Meshtastic-compatible implementation, so the whole household stays uniform.
   GPL at the library root is wrong regardless: these crates sit at the base of
   a permissive ecosystem, and copyleft only flows upward from there.
2. **Firmware images are GPLv3.** The flashable artifact (the retinue-derived
   ESP32/nRF images, and v1's stock RNode firmware) is where GPLv3's teeth
   matter: the installation-information clause means nobody ships a locked
   commercial radio. Direction is fine (MIT/Apache libraries flow into a GPL
   image). Each image should provide a **Bootstrap Console equivalent**: the
   device serves its own firmware source in-band, as RNode firmware does
   (console mode, double reset-press, internal source copy). On flash-tight
   boards (T114, 1MB) where embedding the source does not fit, the fallback is
   the flasher: merecat archives the (image, source) pair for anything it
   flashes, so the source offer travels with the tool, and the device carries a
   pointer.
3. **RNode firmware commercial terms (verified 2026-07-20):** no paid license
   exists; commercial use is gratis conditioned on GPLv3 adherence (source on
   distribution, prominent notices, users told their rights). v1 selling
   boards with RNode firmware complies by doing exactly that.
4. **The standard is defended by trademark + fixtures, not the code license.**
   Public conformance fixtures and the enforced names (retinue, Sennet, Merely)
   are the compatibility lever; Meshtastic demonstrates GPL does not slow
   hardware commercialization, its trademark program is the actual control.
   Qt-style GPL+commercial dual licensing was rejected: it requires a CLA and
   makes Merely the only party with permissive rights, the exact asymmetry the
   "everyone gets the same opportunity" ethos condemns.

## Rejected and benched names (this round)

Rejected: Herald, Dragoman, Legate (all taken on crates.io); Weft (taken, and
Tulle fills the net-fabric lane); Latimer (free, but reads as a surname);
Enmesh (the entangle/ensnare connotation sits crosswise to the fleet-trust
posture). Benched, all verified free: Truchman, Ablegate, Pursuivant, Stentor,
Nuncio, Sennet's sibling spellings, reticella. The Tucket/Sennet assignment is
deliberate: single arrival vs procession encodes which crate is which.
