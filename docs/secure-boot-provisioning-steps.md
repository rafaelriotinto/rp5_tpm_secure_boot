# Secure-Boot Provisioning — Executed Steps (RPi 5)

*Live log of the actual commands run to provision secure boot on the 1 GB
sacrificial board (serial cceddb120af4f481). Every step recorded for thesis
reproduction. Host: Ubuntu desktop. Target: Pi 5 in RPIBOOT mode over USB-C.*

## Terminology / safety

- **RPIBOOT mode**: the BootROM waits for the host to send boot code over USB
  instead of booting from SD/EEPROM. Entered on a regular Pi 5 by holding the
  power button while applying power, then releasing. Momentary — nothing to
  revert. Enumerates on the host as USB `0a5c:2712 Broadcom BCM2712D0 Boot`.
- Nothing is written to EEPROM/OTP until `rpiboot -d <dir>` is run against an
  EEPROM image, and the OTP key-hash burn happens ONLY if `program_pubkey=1`
  is set in that image's config.txt. All steps below up to Phase B/dev-mode
  are read-only or reversible.

## Host tooling: building rpiboot

Source: github.com/raspberrypi/usbboot (cloned to
`$LINUX_YOCTO_RP5_TPM_ENV/usbboot`).

```bash
sudo apt install -y libusb-1.0-0-dev pkg-config   # build deps (gcc/make already present)
cd usbboot
make                                              # builds ./rpiboot + firmware headers
./rpiboot -h                                       # sanity check
```

Built rpiboot version: `e50a7096` (2026/08/17). The build also embeds the
mass-storage-gadget and recovery firmware used below.

Key tools in `usbboot/tools/`:
- `rpi-eeprom-config` — read/modify the config embedded in a pieeprom image
- `rpi-eeprom-digest` — produce boot.sig (hash + RSA signature)
- `update-pieeprom.sh` — apply config + sign the EEPROM image (`-f` counter-
  signs firmware; `-fr` also counter-signs recovery.bin)
- `rpi-otp-private-key` — OTP private-key helper (device-specific key feature)

## Entering RPIBOOT mode (Pi 5)

1. Board off; connect USB-C from host desktop to the Pi's USB-C (power) port.
2. Press and hold the Pi power button.
3. While holding, apply power (the host USB-C provides it).
4. Release the button ~1 s after power-on.
5. Verify on host: `lsusb | grep 0a5c:2712` → `Broadcom BCM2712D0 Boot`.

(If the host USB-C port cannot supply ≥900 mA, power the board via the 40-pin
5V header and use USB-C for data only.)

## Read-only state capture (before any changes) — DONE (2026-08-17)

The minimal Yocto image has no `vcgencmd`, but the kernel exposes OTP directly
via nvmem sysfs (raspberrypi-firmware nvmem driver). Captured from the running
OS over SSH — pure reads:

```bash
# Customer OTP rows (where the secure-boot public-key SHA-256 goes):
hexdump -C /sys/bus/nvmem/devices/nvmem_cust0/nvmem   # 32 bytes
# Device-specific private key region:
hexdump -C /sys/bus/nvmem/devices/nvmem_priv0/nvmem   # 64 bytes
# Full OTP:
hexdump -C /sys/bus/nvmem/devices/nvmem_otp0/nvmem    # 768 bytes
# Also available: nvmem_mac0 (MAC).
```

**Baseline result (virgin board, serial cceddb120af4f481):**
- `nvmem_cust0`: ALL ZERO → secure boot NOT enabled (no customer key hash).
- `nvmem_priv0`: ALL ZERO → device-specific key unused.
- Full OTP 768 bytes; the only non-zero rows are board identity/config
  (revision a04171, SoC serial, MAC-derived bytes) — NOT secure-boot data.

Artifacts saved: `provisioning/baseline/otp_baseline.txt`, `otp_full.txt`.
This is the "before" evidence; re-reading `nvmem_cust0` after Phase C must show
the public-key hash, proving the burn.

EEPROM image backup (via rpiboot/mass-storage-gadget) still to be done before
the first EEPROM write in Phase B.

## Signing key — DONE (2026-08-17)

Generated a fresh RSA-2048 key set (not reusing the Nov 2025 experimental key,
for clean provenance) in `$LINUX_YOCTO_RP5_TPM_ENV/secure-boot-keys/`
(dir 700, private.pem 600):

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl rsa -in private.pem -pubout -outform DER -out public.der
```

**OTP key hash — the value programmed into OTP** (customer key hash):
It is NOT a plain SHA-256 of the DER file. Per the official
`rpi-eeprom/tools/rpi-sign-bootcode` (line ~111), it is:

```
SHA256( N[256 bytes, little-endian] || e[8 bytes, little-endian] )
```

Computed for our key (openssl to extract N/e, no pycryptodome needed):
```bash
N=$(openssl rsa -in private.pem -noout -modulus | sed 's/Modulus=//')
E=$(openssl rsa -in private.pem -noout -text | grep -oE 'publicExponent: [0-9]+' | grep -oE '[0-9]+')
python3 -c "import hashlib; n=int('$N',16); e=int('$E'); \
  print(hashlib.sha256(n.to_bytes(256,'little')+e.to_bytes(8,'little')).hexdigest())"
```

**Our OTP key hash: `0e4da3d85c697bf14d80c93d4257754edc7ab80290b0ce317823182b782160b0`**
(exponent 65537). After the Phase C burn, `nvmem_cust0` must contain this value
→ that is the proof-of-burn check.

CRITICAL: `private.pem` must be backed up in ≥2 safe locations and NEVER placed
in the OS image or boot.img. The key dir is outside any git repo. The thesis
records only the public hash, never the private key.

## Phase B (dev mode, reversible) — DETAILED RECIPE

Reversibility guarantee: the Pi 5 secure-boot flow only becomes irreversible
when `program_pubkey=1` is set in `secure-boot-recovery5/config.txt` and
flashed. That line is COMMENTED OUT for all of Phase B. Signing + flashing the
EEPROM here activates signature *verification* and embeds our public key, but
does NOT burn OTP → the factory EEPROM can be restored at any time.

### B.0 Host prerequisite (one-time) — DONE (2026-08-17)
```bash
sudo apt install -y python3-pycryptodome   # provides the 'Cryptodome' namespace
```
Notes learned:
- The package installs as `Cryptodome` (not `Crypto`); the current
  `rpi-eeprom/rpi-eeprom-config` imports `Cryptodome` → compatible.
- usbboot was cloned with `--depth 1`; the firmware binaries
  (`firmware/2712/pieeprom.bin`, `secure-boot-recovery5/pieeprom.original.bin`)
  are symlinks into the `rpi-eeprom` SUBMODULE. Initialize it:
  `cd usbboot && git submodule update --init --depth 1 rpi-eeprom`.
- Toolchain verified read-only: `python3 rpi-eeprom/rpi-eeprom-config
  secure-boot-recovery5/pieeprom.original.bin` prints the config.
- OTP hash cross-checked with the official Cryptodome method → matches
  `0e4da3d8...782160b0`.
- The bundled reference EEPROM is `pieeprom-2026-05-26` — NEWER than the
  board's running May-2025 bootloader; flashing the signed image also updates
  the bootloader firmware to this version (expected; secure boot needs a
  recent bootloader).

### B.1 Back up the current (factory) EEPROM — DO BEFORE ANY WRITE
Enter RPIBOOT mode (power button hold + USB-C), then expose storage via the
mass-storage gadget and read the SPI flash:
```bash
cd usbboot && ./rpiboot -d mass-storage-gadget64
# board appears on host as a USB block device (dmesg → /dev/sdX);
# the bootloader SPI flash is one of the small exposed devices.
# Save a full backup image:
sudo dd if=/dev/sdX of=pieeprom-factory-backup.bin bs=1M
```
(Exact device node recorded when executed. Keep this backup — it restores the
original bootloader if anything goes wrong.)

### B.2 Build the signed EEPROM image (dev mode, no OTP)
Work in a copy of `usbboot/secure-boot-recovery5/` (Pi 5 / BCM2712 dir):
- `boot.conf` — bootloader config to embed. Default is sensible:
  `BOOT_ORDER=0xf2461` (SD first, then USB/NVMe/network),
  `ENABLE_SELF_UPDATE=0` (block unsigned bootloader auto-updates),
  `BOOT_UART=1`, `POWER_OFF_ON_HALT=1`.
- `config.txt` — MUST keep `program_pubkey=1` COMMENTED (dev mode).

Sign the EEPROM + counter-sign firmware with our key:
```bash
KEY=$LINUX_YOCTO_RP5_TPM_ENV/secure-boot-keys/private.pem
cd usbboot/secure-boot-recovery5
../tools/update-pieeprom.sh -f -k "${KEY}"
# produces signed pieeprom.bin (+ pieeprom.sig); embeds our public key.
```
(`-f` counter-signs the firmware, required on BCM2712. `-r`/`-fr` counter-signs
recovery.bin — only needed AFTER secure boot is enabled, not in dev mode.)

### B.3 Flash the signed EEPROM via rpiboot (reversible)
Enter RPIBOOT mode again, then:
```bash
cd usbboot/secure-boot-recovery5
mkdir -p metadata
../rpiboot -d . -j metadata
```
After this the bootloader verifies boot.img/boot.sig against our key, but OTP
is still virgin (nvmem_cust0 all zero — re-check to confirm).

### B.4 Build + sign boot.img
```bash
# build the Pi5 boot.img (see docs/research-bootimg-blkmap.md level-2):
usbboot/tools/rpi-make-boot-image -d bootfs/ -o boot.img -a 64
# sign it → boot.sig (SHA256 digest + RSA signature):
usbboot/tools/rpi-eeprom-digest -i boot.img -o boot.sig -k "${KEY}"
# place boot.img + boot.sig on the SD boot partition (scp/SSH).
```

### B.5 Validate (days of testing before Phase C)
- Signed boot.img boots normally.
- A TAMPERED or UNSIGNED boot.img is REJECTED by the bootloader (capture the
  serial log of the rejection — thesis evidence).
- Re-confirm `nvmem_cust0` still all-zero (OTP untouched).
- Optionally restore the factory EEPROM (B.1 backup) to prove full
  reversibility, then re-flash the signed one.

## Phase C (OTP burn, IRREVERSIBLE) — GATED

Only after Phase B is validated (several clean dev-mode boots).

Pre-burn checklist (ALL must be true):
- [ ] Factory EEPROM backup exists (B.1) and restore was rehearsed.
- [ ] private.pem backed up in >=2 safe locations (DONE 2026-08-17).
- [ ] Signed boot works AND tampered boot rejected in dev mode.
- [ ] nvmem_cust0 confirmed still zero before the burn.
- [ ] Tutor sign-off on burning the sacrificial board.

Burn:
```bash
cd usbboot/secure-boot-recovery5
# edit config.txt: uncomment  program_pubkey=1
# (optional: recovery_reboot=1 to auto-reboot after flashing)
../tools/update-pieeprom.sh -f -k "${KEY}"   # re-sign with program_pubkey set
mkdir -p metadata && ../rpiboot -d . -j metadata   # flashes + programs OTP
```
IRREVERSIBLE: writes SHA256(N||e) of our key to OTP customer rows, permanently
enforces signed boot, and disables loading recovery.bin from SD/EMMC.

Proof of burn:
```bash
# after reboot, from Linux:
hexdump -C /sys/bus/nvmem/devices/nvmem_cust0/nvmem
# must now contain: 0e4da3d85c697bf14d80c93d4257754edc7ab80290b0ce317823182b782160b0
```
Final test: an unsigned/wrong-key boot.img must fail to boot even after power
cycle (enforcement is now in OTP, not just EEPROM config).

## Status

- 2026-08-17: rpiboot built (e50a7096). Board enters RPIBOOT mode via USB-C +
  power-button. Read-only state capture is the next action; no EEPROM/OTP
  writes performed yet.
