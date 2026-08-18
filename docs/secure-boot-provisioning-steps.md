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

DONE 2026-08-17. Verified:
- Safety: `program_pubkey=1` confirmed COMMENTED in config.txt before signing
  → this image does NOT burn OTP.
- Outputs: pieeprom.bin (2 MB) + pieeprom.sig produced.
- Read-back config (`rpi-eeprom-config pieeprom.bin`) shows our boot.conf.
- Confirmed OUR public key modulus (little-endian) is embedded in pieeprom.bin.
- Reverting later = flash the unsigned reference `pieeprom.original.bin`
  (2026-05-26) via rpiboot (Option A: no per-board backup; generic recovery).

### B.3 Flash the signed EEPROM via rpiboot (reversible) — DONE (2026-08-17)

Executed:
- Board entered RPIBOOT mode (power-button method); enumerated as 0a5c:2712.
- Final safety check before flashing: `program_pubkey=1` confirmed absent
  from config.txt (dev mode).
- Flash required root for raw USB access; either run rpiboot with sudo or add
  a udev rule for vendor 0a5c (first unprivileged attempt failed with
  "Permission to access USB device denied").
- `sudo ../rpiboot -d . -j metadata` output: bootcode5.bin sent -> second
  stage boot server -> config.txt/pieeprom.bin/pieeprom.sig loaded ->
  "Second stage boot server done".
- rpiboot wrote a per-device metadata JSON (saved:
  `provisioning/baseline/flash-metadata-devmode-0af4f481.json`), the device's
  own record of the flash:
  - EEPROM_UPDATE: "success"
  - EEPROM_HASH: 50257d797c803383095209e66908ee61ecc08bc4eb0f5aa69b4150cda084e2de
  - CUSTOMER_KEY_HASH: all zeros  -> OTP untouched (dev mode confirmed)
  - SIGNATURE_MODE: 0, JTAG_LOCKED: 0
  - USER_BOARDREV: a04171; FACTORY_UUID: 000000911045808726 = the DUID read
    earlier from /chosen/rpi-duid (cross-channel identity confirmation);
    MAC_ADDR/WIFI/BT: 88:a2:9e:82:bb:4d/4f/52.

(original planned commands below)

Enter RPIBOOT mode again, then:
```bash
cd usbboot/secure-boot-recovery5
mkdir -p metadata
../rpiboot -d . -j metadata
```
After this the bootloader verifies boot.img/boot.sig against our key, but OTP
is still virgin (nvmem_cust0 all zero — re-check to confirm).

### B.4 Build + sign boot.img — DONE (2026-08-17)

Executed and validated (details below). Key architectural addition: the whole
U-Boot->Linux boot path is COMPILED INTO U-Boot (CONFIG_BOOTCOMMAND with the
blkmap sequence + bootflow-scan fallback) and CONFIG_ENV_IS_NOWHERE=y closes
the unsigned-uboot.env override hole (verified live: a stale uboot.env with the
old bootcmd silently overrode the built-in one until removed). boot.img now
contains config.txt, cmdline.txt, DTB, overlays, kernel_2712.img (U-Boot with
built-in bootcmd), Image. Autonomous boot from inside boot.img verified on
serial ("Loading Environment from nowhere", blkmap map, Image read at RAM
speed, kernel starts). PCR0 note: rebuilt U-Boot => new S-CRTM version string
=> new PCR0 golden value (stable per binary; record per-build at provisioning).

```bash
# build the Pi5 boot.img (see docs/research-bootimg-blkmap.md level-2):
usbboot/tools/rpi-make-boot-image -d bootfs/ -o boot.img -a 64
# sign it → boot.sig (SHA256 digest + RSA signature):
usbboot/tools/rpi-eeprom-digest -i boot.img -o boot.sig -k "${KEY}"
# place boot.img + boot.sig on the SD boot partition (scp/SSH).
```

### B.3b FAILURE + FIX (2026-08-17) — counter-signing pitfall (IMPORTANT)

The first B.3 flash used `update-pieeprom.sh -f` (firmware counter-signing per
the Pi5 README). Result: UNBOOTABLE board — solid red LED, zero serial output,
because the BCM2712 ROM rejects a customer-counter-signed second stage when the
OTP customer key hash is still zero (the ROM "checks against a key hash of
zero" — documented for recovery.bin in secure-boot-recovery5/README.md; applies
equally to the flashed bootsys). The `-f` flow implicitly assumes OTP is being
programmed in the same operation.

Recovery + correct dev mode (from the Pi4 secure-boot-recovery README):
- `SIGNED_BOOT=1` added to boot.conf → bootloader ONLY loads boot.img and
  verifies it against boot.sig (development mode; becomes implicit+permanent
  once OTP is burned).
- Sign WITHOUT `-f`:  `../tools/update-pieeprom.sh -k "$KEY"`  (config signed,
  public key embedded, bootsys NOT counter-signed → ROM accepts on zero-OTP).
- Reflash via rpiboot (board recovered; RPIBOOT lives in ROM and always works).
- After flashing, firmware signals success with a FAST-BLINKING GREEN LED and
  waits for power cycle (no recovery_reboot set).

LESSON (thesis): `-f`/`-fr` counter-signing belongs exclusively to the Phase C
OTP-burn flash. Dev mode = config-signature only + SIGNED_BOOT=1.

### B.3c First verified boot — SUCCESS (2026-08-17)

Serial evidence of the complete chain (new EEPROM 2026-05-26):
```
RPi: BOOTLOADER release VERSION:086b83e3 DATE: 2026/05/26
secure-boot
Loading boot.img ...
boot.sig
rsa2048: 76603a6c...            <- our signature
Verifying / RSA verify
rsa-verify pass (0x0)           <- BL2 verified boot.img with OUR key
U-Boot 2024.04 (Aug 17 2026)    <- booted from inside the verified image
[MBOOT] ... -> PCR 0            <- measured boot active
Created "bi" ... 5.2 GiB/s      <- Image loaded from inside boot.img (blkmap)
Starting kernel ...
```

Post-boot state:
- PCR8/9 unchanged golden values (kernel/initrd identical).
- PCR0/PCR1 have NEW values (bootloader version in DT; secure-boot state in
  /chosen; expected) and are STABLE across two consecutive verified boots →
  these are the golden values for the secure-boot configuration.
- nvmem_cust0 re-checked: ALL ZERO (OTP untouched; dev mode fully reversible).

### B.5 Tamper-rejection test — DONE (2026-08-18), the "prevention" evidence

Goal: prove the bootloader REFUSES a tampered boot.img while still reversible.

PITFALL first (documented so nobody repeats it): initial attempts to corrupt
boot.sig ON THE BOARD silently failed -> board kept booting fine (false
negative). Causes: (a) BusyBox `dd` has NO `conv=notrunc` (write no-op'd);
(b) a nested-quoted python one-liner over SSH mangled and errored. ALWAYS
verify the on-card md5 actually changed before concluding anything.

Reliable method: corrupt on the HOST, scp over, VERIFY on-board md5 == bad,
then reboot:
```bash
scp root@dev:/boot/boot.sig boot.sig.bad
python3 -c "d=bytearray(open('boot.sig.bad','rb').read());   [d.__setitem__(i,d[i]^1) for i in range(8)]; open('boot.sig.bad','wb').write(d)"
scp boot.sig.bad root@dev:/boot/boot.sig
ssh root@dev 'sync; md5sum /boot/boot.sig'   # confirm == corrupted md5
```

RESULT (serial, archived provisioning/baseline/tamper-rejection-serial.txt):
```
secure-boot
Loading boot.img ...
boot.sig
Verifying
Bad signature boot.img
Error 12 loading boot.img
... Failed to open partition 2/3/4/5 ... Retry SD 1 ...
(loops; NEVER reaches U-Boot or kernel)
```
The bootloader detected the signature mismatch, refused boot.img, fell through
the entire BOOT_ORDER (all fail), and retried indefinitely. U-Boot/kernel/login
never appeared. This is the secure-boot PREVENTION proof, complementing the
firmware-level bad-sig rejection (3c experiment). Recovery: restore boot.sig
(a good copy was kept as /boot/boot.sig.good) via the SD reader, since the
board cannot SSH while refusing to boot.

### B.5b Extended validation (days of testing before Phase C)
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
