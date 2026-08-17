# Research: Reading files from inside boot.img in U-Boot (RPi5 secure boot)

*Source-level investigation of the U-Boot tree (`rafaelriotinto/u-boot`, branch
`rpi5-tpm-measured-boot`, HEAD `170b76b675`), August 2026. Basis for the
secure-boot-phase boot flow.*

## Problem

With RPi5 secure boot enabled, BL2 reads a single signed FAT-image file
`boot.img` (+ `boot.sig`) instead of loose files. U-Boot (BL3, loaded from
inside it) must then load kernel/DTB that live *inside* boot.img — the stock
bootstd flow (`bootflow scan` → loose `boot.scr`/`extlinux.conf` on the FAT
partition) finds nothing.

## Key finding: blkmap solves this with ZERO C changes

U-Boot 2024.04 ships the `blkmap` driver (`drivers/block/blkmap.c`,
`cmd/blkmap.c`, `doc/usage/blkmap.rst`) — U-Boot's loop-device equivalent.
It can map a RAM region as a block device, after which the normal FAT driver
reads the image directly:

```
blkmap create <label>
blkmap map <label> <blk#> <cnt> mem <addr>     # hex args
blkmap get <label> dev <var>
fatload blkmap <devnum> ...
```

Not enabled in `rpi_arm64_defconfig` — add `CONFIG_BLKMAP=y` +
`CONFIG_CMD_BLKMAP=y` to `uboot-tpm.cfg`.

Known doc bug in `doc/usage/blkmap.rst` example: it divides the un-rounded
`filesize`; correct sequence is
`setexpr blks ${filesize} + 0x1ff` then `setexpr blks ${blks} / 0x200`.

C API alternative if ever needed: `blkmap_create_ramdisk()` in
`include/blkmap.h:96-105`.

## Firmware-side facts (verified in tree)

- The VideoCore firmware hands U-Boot ONLY the DTB address in `x0`
  (`board/raspberrypi/rpi/lowlevel_init.S:14-27` → `fw_dtb_pointer`,
  `rpi.c:34`). No boot.img address, no ramdisk pointer. Nothing in
  `arch/arm/mach-bcm283x/` or board code references boot.img/tryboot.
- `bcm2712_mem_map` (`arch/arm/mach-bcm283x/init.c`) maps only the FIRST 1 GiB
  of DRAM as normal memory — all script addresses must stay below 0x4000_0000.

## Current boot flow (verified)

- Environment is a text file `board/raspberrypi/rpi/rpi.env`:
  `kernel_addr_r=0x00080000`, `scriptaddr=0x02400000`, `fdt_addr_r=0x02600000`,
  `ramdisk_addr_r=0x02700000`, `boot_targets=mmc usb pxe dhcp`.
- `CONFIG_BOOTSTD_DEFAULTS=y` → default `bootcmd` is `bootflow scan` →
  script/extlinux bootmeths find meta-raspberrypi's loose `boot.scr` today.
- blkmap has no bootstd/bootdev integration — explicit commands (or a sourced
  boot.scr) required.
- SECURITY: defconfig has `CONFIG_ENV_FAT_DEVICE_AND_PART="0:1"` — saved env
  as unsigned `uboot.env` on the FAT partition. Under secure boot switch to
  `CONFIG_ENV_IS_NOWHERE=y` (unsigned env could alter boot commands).

## Options compared

- (A) **blkmap mem mapping — winner**: present, scriptable, zero C.
- (B) `host bind` loopback: sandbox-only (`drivers/block/Makefile:15`), N/A.
- (C) custom FAT-in-file reader: 200-400 LOC of new TCB, unjustified.
- (D) firmware-passed boot.img address: does not exist; even if residue found
  in RAM, undocumented behavior — don't rely on it.

## Recommended plan

Config additions to `uboot-tpm.cfg`:

```
CONFIG_BLKMAP=y
CONFIG_CMD_BLKMAP=y
CONFIG_ENV_IS_NOWHERE=y
```

Boot sequence (bootcmd override or signed boot.scr inside boot.img):

```
setenv bootimg_addr 0x20000000
fatload mmc 0:1 ${bootimg_addr} boot.img
setexpr bootimg_blks ${filesize} + 0x1ff
setexpr bootimg_blks ${bootimg_blks} / 0x200
blkmap create bi
blkmap map bi 0 ${bootimg_blks} mem ${bootimg_addr}
blkmap get bi dev devnum
fatload blkmap ${devnum} ${kernel_addr_r} Image
booti ${kernel_addr_r} - ${fdt_addr}
```

Notes:
- Staging at 0x2000_0000 (512 MiB) clears kernel/DTB/ramdisk growth from below
  and stays inside the 1 GiB normal-memory map. boot.img must not be
  overwritten until the last fatload from it completes.
- Boot with the FIRMWARE DTB (`${fdt_addr}`) — overlays/config.txt tweaks are
  already applied there; measured boot then measures what is actually booted.
- Optional: measure a hash of whole boot.img before parsing → attests
  config.txt/overlays for free.
- Yocto side: recipe to pack IMAGE_BOOT_FILES into boot.img (rpi-eeprom
  tooling) + sign boot.sig — packaging work, not U-Boot work.
- Testable BEFORE enabling secure boot: hand-make a boot.img, place it on the
  normal FAT partition, run the sequence at the U-Boot prompt.

## Open questions / hardware tests

1. FAT autodetect on partition-table-less image: `fatls blkmap <dev>` vs
   `fatls blkmap <dev>:0` — 2-minute test.
2. Curiosity: does BL2 leave boot.img residue in RAM? (`md` for FAT signature;
   don't depend on it.)
3. Confirm `fatload mmc 0:1` still works under secure boot BEFORE OTP burn.
4. boot.scr-inside-boot.img (re-signable flexibility) vs compiled-in bootcmd
   (immutable) — both inside the signature envelope.
5. Verify nothing depends on saveenv/uboot.env before ENV_IS_NOWHERE.

## Level-1 validation — DONE (2026-08-17, on hardware)

Interactive test at the U-Boot prompt (blkmap-enabled build of the same day),
with a hand-made 40 MB FAT boot.img (Image + DTB) placed as a plain file on
the normal boot partition:

- `fatload mmc 0:1 0x20000000 boot.img` — 40 MB in 1.7 s
- `blkmap create` + `map ... mem` — mapped (0x14000 blocks)
- `fatls blkmap <dev>` — lists Image + DTB from inside the RAM image
- `fatload blkmap <dev> ${kernel_addr_r} Image` — 27.9 MB in 8 ms (3.2 GiB/s)
- `booti` with marker bootargs — Linux booted; `/proc/cmdline` shows the
  marker (kernel provably from inside boot.img)
- PCR8 unchanged (same kernel bytes); PCR1 changed due to the marker —
  incidental live proof that cmdline tampering is measurement-visible.

FAT autodetect on the partition-table-less image worked without a partition
suffix (open question 1 resolved). Next: level 2 — full boot.img with inner
config.txt, boot_ramdisk=1, digest boot.sig; then Yocto packaging recipe.
