# FCC posture for reselling flashed LoRa radios

**Date:** 2026-07-20
**Status:** Research findings + decided v1 posture. Not legal advice; counsel
review before scaling past friends-and-family volume.
**Context:** Merely LLC (registered Kentucky 2026-07-19) intends to sell Heltec
LoRa boards running Reticulum (RNode firmware now, retinue-derived later),
managed through merecat. Question: is flash-and-resell lawful?
**Siblings:** `2026-07-19_modem_embedded_and_meshtastic_research.md`,
`2026-07-20_mesh_household_tulle_tucket_sennet.md`.

## The rules, in four steps

1. **The boards are certified devices.** Heltec holds FCC grantee code 2A2GJ.
   The T114's radio is granted as FCC ID 2A2GJ-HT-N5262 (filed 2024-10-12,
   Part 15C, 902-915 MHz LoRa + 2.4 GHz BLE). It is not a modular grant, and
   the certified peak conducted power on the LoRa band is only ~18 mW. The
   SX1262 can emit 158 mW and RNode firmware exposes TX power as a user knob,
   so firmware that permits operation beyond the tested envelope is exactly the
   kind of change the FCC cares about.
2. **Whoever modifies, owns it.** 47 CFR 2.909(d): a party who modifies
   certified equipment without the grantee's authority becomes the responsible
   party for compliance. Flash-and-resell makes Merely the responsible party.
3. **Third-party firmware changes to radio parameters are not a permissive
   change.** FCC KDB 178919: on non-SDR devices, third-party software changes
   to frequency, power, or modulation are not allowed; permissive changes
   belong to the grantee alone. "Our firmware stays inside the certified
   envelope" is good engineering posture but not, by itself, a safe harbor for
   marketing the modified device.
4. **The dev-kit loophole runs the wrong way.** 47 CFR 2.803's evaluation-kit
   exemption permits sales to developers only, and assembled kits "may not be
   resold or otherwise marketed unless all required FCC equipment
   authorizations are first obtained." It protects Heltec selling to us, not
   us selling finished nodes to consumers.

Enforcement reality: base forfeiture for marketing unauthorized RF devices is
about $7,000 per violation; actual enforcement against small LoRa sellers is
essentially absent (pre-flashed nodes are all over Etsy). But a business
seeking investment cannot diligence on "nobody's been caught," and marketplaces
and retail partners ask for the FCC ID.

## The three paths, in order of when to use them

- **v1, clean today: sell stock certified hardware; flashing is the customer's
  one click.** Merely resells unmodified certified devices (distributor role,
  no new obligations) and merecat ships a flasher that makes "flash to
  Reticulum" a single button. End users modifying their own devices is a
  regime the FCC does not police, and Merely never markets a modified RF
  device. Barely worse UX than pre-flashed, arguably better branding.
- **Growth: Heltec's written authorization.** 2.909(d)'s escape hatch:
  modifications made under the grantee's authority keep responsibility with
  the grantee. Heltec actively courts the open-firmware ecosystem; a written
  authorization for a retinue firmware variant may be a cheap email. Attempt
  before path three.
- **Scale: Merely's own FCC ID.** What the incumbents do: RAK and Seeed
  certify finished products with the open firmware installed; distributors
  resell those certified units. Ballpark $8-15k per device family through a
  test lab, less with Heltec's test data. A milestone purchase, not a
  prerequisite.

## Standing requirement regardless of path: region-locked firmware

Any firmware Merely ships or flashes hard-caps TX power, frequency, and duty
cycle to the certified envelope (as Meshtastic's region setting does). This is
simultaneously the substantive-compliance story, the Heltec-negotiation asset,
and the right product default. retinue owns the config surface through
merecat, so the cap is ours to enforce. Ties into Tulle's duty-cycle gate (see
the mesh-household doc): one place where airtime discipline is enforced for
all protocols.

## Side note: RNode commercial licensing (corrected 2026-07-20)

Separate from FCC: there is NO paid commercial license for RNode firmware.
Commercial use (including selling flashed devices) is granted free of charge,
conditioned on GPLv3 adherence: up-to-date source upon distribution, prominent
copyright/license notices, and making users aware of their GPLv3 rights
(unsigned.io/rnode_firmware, unsigned.io/sell_rnodes). The firmware's own
Bootstrap Console (console mode via double reset-press) serves the device's
internal copy of its firmware source, which is in-band source provisioning.
Merely's v1 complies by keeping notices intact and devices flashable; our own
future firmware images adopt the same posture (see the licensing ruling in the
mesh-household doc).

## Sources

- 47 CFR 2.909 (responsible party): ecfr.gov/current/title-47/.../section-2.909
- KDB 178919 D01 Permissive Change Policy: apps.fcc.gov/kdb (tracking 33013)
- 47 CFR 2.803 (marketing prior to authorization, evaluation kits):
  law.cornell.edu/cfr/text/47/2.803
- Pillsbury, "A Primer on FCC RF Device Equipment Authorization Rules"
- Heltec FCC filings: fcc.report/company/Heltec-Automation-Technology-Co-L-T-D
- FCC ID 2A2GJ-HT-N5262: fccid.io/2A2GJ-HT-N5262
- RNode firmware + commercial license: unsigned.io/rnode_firmware
