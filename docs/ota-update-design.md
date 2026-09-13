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


## Settled design (2026-09-13): pairs by rule, one signed image per release

The A/B flow above covers the BOOT image. With a dm-verity root the root
filesystem is part of the release too (its root hash is inside the signed
`cmdline.txt`), so a slot is a PAIR (boot partition + root partition), and the
question was how one signed `boot.img` can name the root device for both slots.

**Rule, not flavour.** `cmdline.txt` carries the placeholder `@ROOTDEV@`.
U-Boot (`board_fdt_chosen_bootargs()` in `board/raspberrypi/rpi/rpi.c`, fork
commit `8e021abd`) reads the partition the firmware booted from
(`/chosen/bootloader/partition`) and substitutes by a fixed rule:

| firmware booted from | root device | pair |
|---|---|---|
| partition 1 (boot A) | `/dev/mmcblk0p2` | A |
| partition 5 (boot B) | `/dev/mmcblk0p3` | B |

Anything else, or an unresolved placeholder, halts. Consequences:
- one signed `boot.img` per release, identical bytes in both boot partitions;
- the update always writes the INACTIVE pair, whatever version it holds
  (a board two releases behind is updated exactly like one release behind);
- a failed tryboot reverts to the untouched pair: nothing to swap back;
- PCR1 measures the SUBSTITUTED line, so a release has two PCR1 goldens (one
  per pair), both computable on the host from the template. PCR0 carries the
  template (the firmware DT holds `cmdline.txt` verbatim) and is the same on
  both pairs. Validated: `experimental-results.md` E12.

**Layout (GPT), `meta-rpi5-uboot-tpm/wic/rpi5-verity-ab.wks.in`:**

| # | label | content |
|---|---|---|
| p1 | boota | FAT: `boot.img` + `boot.sig`, `autoboot.txt` |
| p2 | root A | raw verity image (fixed 512 MiB) |
| p3 | root B | raw verity image (fixed 512 MiB) |
| p4 | data | ext4, `noexec,nosuid,nodev` |
| p5 | bootb | FAT: `boot.img` + `boot.sig` |

`autoboot.txt` (recipe `rpi-autoboot`, read by the firmware from p1 only):

```
[all]
tryboot_a_b=1
boot_partition=1
[tryboot]
boot_partition=5
```

**Release = one monotonic version** covering U-Boot + kernel + DT + config +
rootfs: the root hash in the signed cmdline binds the rootfs to the boot
image, so there is nothing to version separately. Manifest: version,
`boot.img` digest, verity image digest, PCR0, PCR1 (A and B), PCR8, PCR9.

**Update procedure (agent, step 5 of the plan):**
1. Read the active pair from `/chosen/bootloader/partition`; the target is the
   other one. Refuse to touch the active pair (lesson from E11: writing the
   running root corrupts the live system).
2. Write the verity image to the target root, `fsync`, read back and compare
   the digest against the manifest.
3. Write `boot.img` + `boot.sig` to the target boot partition (FAT), read back.
4. `reboot "0 tryboot"` -> firmware boots the `[tryboot]` partition once. The
   firmware verifies that `boot.img` like any other (owner key in OTP).
5. Health check in the new system (verity root mounted, attestation passes,
   TPM anti-rollback counter advanced) -> COMMIT by rewriting `autoboot.txt`
   on p1 with the two partition numbers swapped. Otherwise do nothing: the
   next reboot returns to the committed pair.

**First flash of the A/B card (host, card in reader as /dev/sdX):**
1. `bmaptool copy` / `dd` the `.wic` image. wic populates the boot partitions
   with the raw firmware files, NOT the signed `boot.img`: under secure boot
   the card will not boot yet.
2. Build the release `boot.img` from the deployed U-Boot, kernel, DTs,
   overlays, `config.txt` and the TEMPLATE `cmdline.txt` (root hash and salt
   of the `.verity` image just flashed, from its `.verity.env`; the
   `dm-mod.create` string via `provisioning/verity/verity-cmdline.sh`);
   sign with `rpi-eeprom-digest`.
3. `mcopy` `boot.img` + `boot.sig` into BOTH p1 and p5.
4. Boot; expect partition 1, root A, PCR1 = golden A. Then the tryboot spike:
   `reboot "0 tryboot"` -> expect partition 5, root B, PCR1 = golden B, PCR0
   unchanged; then a plain reboot -> back to pair A (nothing committed).

## The update cycle, as it runs on the board (reference walkthrough, 2026-09-13)

Only one piece of state says which pair is current: `autoboot.txt` on p1.
`[all] boot_partition=N` names the COMMITTED pair; `[tryboot] boot_partition=M`
names the OTHER pair, which is both the install target and what a trial boots.
The two pairs are symmetric (one signed `boot.img` works from either boot
partition; the root is chosen by rule from the partition the firmware
reports). The firmware only ever READS this file; the agent WRITES it exactly
once per update, at commit.

1. **Install** (agent, running system): target = the `[tryboot]` pair. Refuse
   if it equals `/chosen/bootloader/partition`. Write the verity image raw to
   the target root, `boot.img`+`boot.sig` to the target boot partition, read
   both back against the manifest. `autoboot.txt` untouched: an interruption
   here changes nothing for the next boot.
2. **Trial** (`reboot "0 tryboot"`): Linux passes the string to the firmware,
   which stores a tryboot bit in a reset-persistent register. On the next
   boot the firmware takes `boot_partition` from `[tryboot]`, CLEARS the bit,
   verifies that pair's `boot.img`, reports partition and `tryboot=1` in the
   DT. U-Boot selects the root by rule, measures, checks anti-rollback
   WITHOUT advancing the counter (tryboot), boots. Any failure (refusal
   reset, panic/watchdog, power loss, nobody commits) ends on the committed
   pair, because the bit is already consumed and the file still names it.
3. **Health check** (agent + server): agent confirms it is the trial
   (`tryboot=1`), the intended verity root, required services; the SERVER
   runs an attestation round (goldens of the new release, NV commitment,
   resetCount advanced) and answers commit / no commit. The counter has not
   moved, so "no" costs nothing.
4. **Commit** (agent, from the trial system): rewrite `autoboot.txt` with the
   two numbers swapped (temp file, sync, rename, sync). Then plain `reboot`.
5. **First committed boot**: firmware reads `[all]`, `tryboot=0`; U-Boot
   advances the anti-rollback counter to this release's version (read back),
   boots; server records the version as committed. From here any lower
   version is refused on this board, the previous pair included.
6. **Afterwards**: the other pair holds the previous release until the next
   install overwrites it. A bad release found after commit is fixed forward
   (new signed release, higher version); a board that skipped releases is
   updated exactly like any other (target = the `[tryboot]` pair, counter
   catches up in one committed boot).

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
- 2026-09-13: pairing-by-rule implemented in U-Boot and validated on the
  existing card (E12). GPT A/B layout + `autoboot.txt` recipe committed;
  first flash and the tryboot-under-secure-boot spike pending (needs the card
  in a reader).
- 2026-09-13 (later): E13 — firmware numbers GPT partitions by counting basic-data-typed
  partitions only → layout reordered (boot A | boot B | root A | root B | data, roots typed
  Linux fs; U-Boot rule 1 → p3, 2 → p4). tryboot under secure boot works. Boot command fixed to
  load `boot.img` from the booted partition (`${rpi_bootpart}`). First real update r2 → r3
  performed by hand exactly as in "Update procedure" and committed. Remaining: the agent script
  (step 5), anti-rollback counter, event log to Linux.
- 2026-09-13 (evening): services implemented (`agents/`), first automated update r7→r8 by
  `rp5.py update` (E16). Remaining: provisioning service test, PCR0 without TOFU.
