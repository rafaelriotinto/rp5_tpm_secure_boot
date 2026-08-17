# Research: Sanitizing the RPi5 firmware DTB before TPM PCR0 measurement

*Source-level investigation of the U-Boot tree (`rafaelriotinto/u-boot`, branch
`rpi5-tpm-measured-boot`, HEAD `170b76b675`), August 2026. Basis for the
measured-boot DT-sanitization implementation.*

## Problem

The RPi5 proprietary BL2 assembles the device tree in RAM (base dtb + overlays)
and injects boot-varying data (at least a reset counter/reason; confirmed
`/chosen/kaslr-seed`). U-Boot's measured boot hashes that blob verbatim into
PCR 0, so the measurement differs on every boot, defeating attestation.

## Current measurement flow (verified)

- `bootm_run_states()` runs `BOOTM_STATE_MEASURE` at `boot/bootm.c:1084-1086` —
  after `bootm_find_other()` resolves the FDT but **before** FDT relocation
  (`:1112-1116`) and before `image_setup_libfdt` fixups (`boot/image-fdt.c:602/637`).
  What is measured is the raw firmware-assembled DTB; U-Boot's own later
  injections (bootargs, rng-seed via `boot/fdt_support.c:302`) are not included.
- `images->ft_addr` chain: `boot_get_fdt()` (`boot/image-fdt.c:449`) →
  `select_fdt()` (`:293`) → `*of_flat_tree = fdt_blob` (`:541-542`) → points
  directly at the firmware blob (`fw_dtb_pointer`, captured in
  `board/raspberrypi/rpi/lowlevel_init.S:19`, stored `rpi.c:36`, control FDT via
  `board_fdt_blob_setup()` `rpi.c:517-526`). No copy, no normalization.
- PCR0 call (`boot/bootm.c:1013-1016`):
  `tcg2_measure_data(dev, &elog, 0, images->ft_len, (u8 *)images->ft_addr,
  EV_TABLE_OF_DEVICES, strlen("dts")+1, (u8 *)"dts")`.
- `tcg2_measure_data()` (`lib/tpm-v2.c:527`) is a pure hash-this-buffer
  primitive → sanitization must happen before the call; passing a sanitized
  copy is fully transparent to it.
- PCR0 also receives U-Boot's S-CRTM version string during
  `tcg2_measurement_init()` (`lib/tpm-v2.c:668-670`); `tcg2_measurement_term`
  caps PCRs 0-7 with `EV_SEPARATOR`.

## WIP commit 170b76b675 contents (verified)

- `boot/bootm.c` (+77): booti support in `bootm_measure` (falls back to
  `images->os.start` + `env_get("filesize")` so raw ARM64 Images are measured
  with BSS excluded → stable PCR8); event log switched to `malloc(SZ_64K)`;
  `[MBOOT]` instrumentation. **No DTB sanitization.**
- `include/tpm-v2.h` (+2): adds `TPM2_CC_SHUTDOWN = 0x0145` only. NV-extend
  commands not present yet.
- `lib/tpm-v2.c` (+74) and `lib/efi_loader/efi_tcg2.c` (+116): instrumentation
  only, no functional change.

## Dynamic DT content

Confirmed in-tree:
- `/chosen/kaslr-seed` is firmware-injected and boot-varying
  (`board/raspberrypi/rpi/rpi.c:571`, `copy_property(..., "kaslr-seed")`).
- `update_fdt_from_fw()` (`rpi.c:548-575`) items (`/model`, memreserve,
  dma-ranges, blconfig, PHY reg) are board-dependent but stable across boots —
  no stripping needed.
- Reset counter/reason injection is invisible in U-Boot sources (no bcm2712 DTS
  in-tree; RPi5 is pure OF_BOARD) — hardware verification required.

Candidate strip list (verify on hardware):

| Path | Why |
|---|---|
| `/chosen/kaslr-seed` | confirmed firmware-injected, random per boot |
| `/chosen/rng-seed` | firmware-provided entropy, random per boot |
| `/chosen/bootloader/*` | likely home of reset counter/reason (`pm_rsts`, count, boot-mode, tryboot) |
| totalsize padding | handled by `fdt_pack` regardless |

Safest policy: delete the whole `/chosen` node from the measured copy
(bootargs are separately measured into PCR1 at `boot/bootm.c:1031`; U-Boot
re-populates `/chosen` for Linux after measurement).

## Primitives and upstream precedents

- libfdt RW set available: `fdt_open_into` (`scripts/dtc/libfdt/fdt_rw.c:416`),
  `fdt_delprop` (`:319`), `fdt_del_node` (`:380`), `fdt_pack` (`:480`).
- **Precedent 1 (key):** EFI boot path already sanitizes before measuring:
  `lib/efi_loader/efi_helper.c:466-483` — `copy_fdt()` →
  `efi_try_purge_kaslr_seed()` → `efi_tcg2_measure_dtb()`.
  `efi_try_purge_kaslr_seed()` (`lib/efi_loader/efi_dt_fixup.c:54-73`) deletes
  `/chosen/kaslr-seed` with a comment that the seed "would mess up our DTB TPM
  measurements". Our work ports this accepted upstream pattern to the non-EFI
  bootm path.
- Precedent 2: `efi_tcg2_measure_dtb()` (`lib/efi_loader/efi_tcg2.c:1328`)
  hashes only populated FDT areas. (Known upstream bug at `:1372-1373` —
  struct/strings size fields swapped; do not copy verbatim.)
- Upstream's `CONFIG_MEASURE_DEVICETREE` help (`boot/Kconfig:808-815`)
  acknowledges the instability problem; its only remedy is disabling DT
  measurement. Sanitization is the better middle ground.

## Implementation plan

Hook: the `CONFIG_MEASURE_DEVICETREE` block in `bootm_measure()`
(`boot/bootm.c:1009-1023`). New helper:

```c
static int measure_dtb_sanitized(struct udevice *dev,
                                 struct tcg2_event_log *elog,
                                 void *fdt, u32 fdt_len)
```

1. `buf = malloc(fdt_len + SZ_4K)`
2. `fdt_open_into(fdt, buf, fdt_len + SZ_4K)`
3. Strip via small static table: `/chosen/kaslr-seed`, `/chosen/rng-seed`,
   `/chosen/bootloader` node (extend from hardware findings); ignore
   `-FDT_ERR_NOTFOUND`
4. `fdt_pack(buf)`; measure `fdt_totalsize(buf)` bytes into PCR0
   (packing removes slack/padding variance)
5. `free(buf)`; original blob untouched for Linux

Kconfig: `MEASURE_DEVICETREE_SANITIZE` (bool, depends on MEASURE_DEVICETREE,
default n) in `boot/Kconfig:807-825` block; enable from `uboot-tpm.cfg`.
Estimated ~60-80 LOC in bootm.c + ~12 in Kconfig.

Attestation note: the event log carries the sanitized blob's digest; document
the strip+pack rule so a verifier can reproduce the expected hash from a golden
DT.

## Hardware verification — DONE (2026-08-17, on the clean-build image)

Method: `fdt print /` at the U-Boot prompt (warm boot) + md5sum diff of all
2924 files under `/proc/device-tree` between a cold boot and a warm reboot.

**Results:**

- `fdt_totalsize` is stable: 0x144ea (83178 bytes) on both boot types.
- Exactly TWO properties differ between cold and warm boot, both under
  `/chosen/bootloader`:
  - `rsts` — reset reason flags: `0x1000` (power-on) vs `0x1020` (soft reset)
  - `count` — resets since power-on: 1 on cold boot, increments each warm boot
    (varies EVERY boot, not just cold-vs-warm)
- `/chosen/kaslr-seed` and `/chosen/rng-seed` are firmware-injected random
  values (observed at U-Boot time; the kernel consumes/zeroes them so they
  don't appear in the Linux-level diff).
- Everything else in the tree (2920+ files) is bit-identical across boot types.
- The U-Boot `hash` command is not enabled in the current config
  (`CONFIG_CMD_HASH` — add to uboot-tpm.cfg for convenience).

**Final strip list** for the sanitizer:
`/chosen/kaslr-seed`, `/chosen/rng-seed`, and the whole `/chosen/bootloader`
node (covers rsts + count and is future-proof against new firmware state
there). Note `/chosen/bootloader/version`/`build-timestamp` are firmware
identity — deleting the node loses them from PCR0; they are still attestable
via other channels (EEPROM version is fixed by the signed BL2). Everything
else stays measured.
