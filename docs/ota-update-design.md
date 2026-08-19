# OTA Update of boot.img — Design

Planned functionality. A service on the device fetches a new `boot.img` +
`boot.sig` from an update server and installs it on the SD card, so the payload
(U-Boot + kernel + rootfs) can be updated remotely. Design agreed Aug 19 2026;
NOT yet implemented.

## The key insight: OTA integrity is FREE under secure boot

Because BL2 verifies `boot.sig` against the OTP-fused customer key on EVERY boot
(and, per the RPi docs, "secure boot images can be loaded from any of the normal
boot modes -- SD, USB, Network"), the OTA channel does NOT have to be a trusted
path for INTEGRITY/AUTHENTICITY:

- A compromised update service, or a MITM on the download, can at worst deliver
  an image that is ALREADY validly signed by the customer key -- it cannot
  forge a new one without the private key. An unsigned/tampered image is simply
  rejected by BL2 at the next boot.

So the update agent is "untrusted plumbing": secure boot is the backstop. What
the OTA design must still handle is (a) ROBUSTNESS (don't brick on a bad
update) and (b) ROLLBACK (don't let an old signed image be re-installed).

## Robustness: A/B slots + tryboot (no brick on bad update)

The danger of naively overwriting the single `boot.img`: a corrupt download, a
power loss mid-write, or a signature that fails at boot -> the device won't boot
-> physical recovery via SD reader (unacceptable for a remote device).

RPi provides the safe-update primitive: **`tryboot`** + `autoboot.txt` A/B
partition selection.
- `autoboot.txt` on the boot medium selects the active boot partition, with a
  separate `[tryboot]` section for a one-shot alternate.
- `reboot "0 tryboot"` boots ONCE using the tryboot slot; if the OS does not
  confirm success, the next reboot reverts to the known-good slot.

A/B flow:
1. Keep two boot slots (A = active known-good, B = update target), each with its
   own signed `boot.img` + `boot.sig`.
2. Update agent writes the new image to the INACTIVE slot (B) and fsyncs.
3. Optionally verify `boot.sig` LOCALLY before switching (the device holds the
   public key; fail fast instead of at reboot).
4. `tryboot` into B (one-shot).
5. If B boots and passes a health check -> COMMIT (make B the active slot).
6. If B fails to boot -> firmware auto-reverts to A. Device stays up.

NEEDS HARDWARE VERIFICATION: exact `autoboot.txt`/`tryboot` syntax on Pi 5 WITH
secure boot enabled, and that both slots' `boot.sig` are verified the same way.
(tryboot is documented by RPi for OS updates; secure-boot interaction to test.)

## Update agent (on-device service)

Runs on Linux; conceptually:
1. Authenticate to the update server over TLS; identify the device (e.g. via the
   TPM AK once attestation exists).
2. Query current vs available version. Apply anti-rollback policy: refuse to
   install a version <= the TPM anti-rollback counter (see
   anti-rollback-design.md) -- the update agent enforces this BEFORE writing,
   and U-Boot enforces it again at boot (defence in depth).
3. Download `boot.img` + `boot.sig` (+ signed metadata: version, expected golden
   PCR/NV values for attestation).
4. Verify signature locally; write to the inactive slot; fsync.
5. tryboot; on healthy boot, commit; else auto-revert.
6. Report the new state (version, golden values) to the attestation server.

## Composition with the rest of the system

- **Secure boot**: verifies the updated image at boot -- the integrity anchor.
- **Anti-rollback**: the TPM counter ensures OTA cannot install an older signed
  image. The agent checks before writing; U-Boot enforces at boot.
- **Measured boot**: a new `boot.img` yields NEW golden PCR/NV values. The
  update server ships the new golden values (signed) alongside the image so the
  attestation server can update its expectations for that device+version.
- **dm-verity / rootfs** (once done): a new rootfs -> new root hash inside the
  new signed `boot.img`, so one signed blob still covers everything.

## Security analysis (what OTA must / must not guarantee)

| Property | Provided by |
|---|---|
| Only authentic images ever boot | Secure boot (OTP key) -- OTA channel untrusted |
| No downgrade to old signed image | TPM anti-rollback counter (agent + U-Boot) |
| No brick on bad/partial update | A/B slots + tryboot auto-revert |
| Update source authentication | TLS + device identity (AK); secure boot is backstop |
| Image confidentiality (if needed) | TLS in transit; image is not secret on the SD |

Residual: the update agent runs as (root) code on the device; a compromise
there can install any CUSTOMER-SIGNED image (i.e. downgrade within anti-rollback
limits, or DoS by repeatedly failing updates) but cannot run unsigned code.
This bounds the damage to availability, not integrity -- worth stating.

## Implementation plan

- Yocto: partition layout with two boot slots (wic), `autoboot.txt`, and an
  `ota-agent` recipe (a systemd service + updater script; Python or C).
- Build/release pipeline: produce `boot.img` + `boot.sig` (already have the
  tooling: rpi-make-boot-image + rpi-eeprom-digest), plus signed metadata
  (version + golden values).
- Agent: fetch/verify/write-inactive/tryboot/commit-or-revert; hook the
  anti-rollback version check and attestation reporting.
- Depends on: anti-rollback (version policy), attestation (device identity +
  golden-value reporting). Reuses the signing tooling already validated.

## Status

- 2026-08-19: design documented. Sequencing: after secure boot (done),
  anti-rollback, and attestation, since it composes with all three. First
  concrete spike: verify tryboot A/B under secure boot on hardware.
