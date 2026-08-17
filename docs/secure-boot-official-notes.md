# Notes from official RPi secure-boot tooling (usbboot / rpi-eeprom)

*Read Aug 17 2026 from github.com/raspberrypi/usbboot (docs/secure-boot.md,
secure-boot-recovery5/, tools/). Authoritative reference; supersedes my prior
assumptions where they differ.*

## Chain of trust (BCM2712 / Pi 5)

- BootROM (immutable) verifies `bootsys` signed by Raspberry Pi's key.
- **Pi 5 difference**: with secure boot on, the ROM requires `bootsys` to be
  signed by RPi's key **AND counter-signed with the customer key**. So a
  firmware/EEPROM update cannot install unless the customer signs it. (Pi 4
  only checks the RPi key.) → our EEPROM + recovery.bin must be counter-signed.
- `bootsys` loads customer public key from EEPROM, checks its SHA-256 against
  the hash in OTP.
- `bootmain` loads `boot.img` + `boot.sig`, verifies boot.img hash == boot.sig
  and the RSA signature validates against the customer key. With secure boot
  on, firmware loads ONLY from the verified ramdisk.

## boot.img (matches our blkmap plan)

Official required contents of boot.img:
- config.txt
- device tree + overlays
- **GPU firmware (start.elf + fixup.dat)** ← note: firmware goes INSIDE too
- Linux kernel image
- initramfs (app, or scripts to mount encrypted rootfs)

For us the "kernel" inside boot.img is U-Boot (kernel_2712.img); our Image +
DTB + overlays + our two TPM overlays also go in. This is the level-2 image.

Builder: `usbboot/tools/rpi-make-boot-image -d <bootfs_dir> -o boot.img`
(uses mtools, no root needed; -b pi5 prunes to board files). This replaces my
hand-rolled mformat/mcopy approach — use the official tool for the real image.

## Signing

- Key: RSA-2048, `openssl genrsa 2048 > private.pem`. MUST be backed up,
  MUST NOT be in the OS image.
- Sign boot.img: `tools/rpi-eeprom-digest` produces boot.sig (hash + RSA sig).
- EEPROM + recovery counter-sign: `tools/update-pieeprom.sh -f -k KEY_FILE`
  (add `r` → `-fr` once secure boot already enabled, to counter-sign
  recovery.bin too). HSM wrapper supported (`-H`).

## OTP programming (the irreversible step) — CONTROLLED BY config.txt

In `secure-boot-recovery5/config.txt`, all commented out by default:
- `program_pubkey=1` → writes SHA-256 of customer public key to OTP, locks the
  device to it, and **disables loading recovery.bin from SD/EMMC** (bootloader
  then only updatable via RPIBOOT or self-update). IRREVERSIBLE.
- `program_jtag_lock=1` → permanently disables VideoCore JTAG.
- `eeprom_write_protect=1` → marks EEPROM write-protected (needs /WP pin).
- `recovery_reboot=1` → auto-reboot after flashing.

Provisioning is done via **rpiboot** (nRPIBOOT jumper or hold power button),
NOT from the running OS: `cd secure-boot-recovery5; rpiboot -d . -j metadata`.
So OTP burn = flashing a signed EEPROM image over USB in rpiboot mode, with
program_pubkey=1 set. Staged: first flash signed EEPROM WITHOUT program_pubkey
(dev mode, reversible), validate, then flash again WITH program_pubkey (burn).

## Corrections to my earlier assumptions

1. It is NOT just "boot_ramdisk=1 + loose files". Secure boot uses a specific
   signed boot.img ramdisk verified by `bootmain`; the mechanism is built into
   the firmware's secure-boot path, driven by the EEPROM/OTP state, not a
   config flag we toggle casually.
2. GPU firmware (start.elf/fixup.dat) must be INSIDE boot.img too — not just
   kernel+dtb. Our level-1 test image was missing these (fine for the U-Boot
   blkmap test; required for the real BL2 ramdisk boot).
3. Provisioning path is rpiboot-over-USB, not OS-side scripting. Our
   provisioning automation (docs/provisioning-design.md) must drive rpiboot.

## Confirms today's threat analysis (docs/provisioning-design.md 3b)

Official docs state plainly:
- "Raspberry Pi computers do not have a secure hardware enclave"; the OTP key
  "is accessible to any process with access to /dev/vcio (vcmailbox)".
- "It is not possible to prevent code running in ARM supervisor mode (e.g.
  kernel code) from accessing OTP hardware directly."

This is upstream confirmation of our scoping: no on-device root-unreachable
secret exists. Cite in the thesis threat model.

## rpi-sb-provisioner

RPi's official provisioning app is github.com/raspberrypi/rpi-sb-provisioner —
worth studying as prior art / comparison for our automated provisioning
(docs/provisioning-design.md), and to cite.
