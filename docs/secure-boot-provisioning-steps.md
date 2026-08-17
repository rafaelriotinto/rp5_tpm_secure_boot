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

## Phase B (dev mode, reversible) — NOT YET STARTED

1. ~~Generate/locate RSA-2048 key~~ DONE (above). Back up private.pem.
2. Build + sign boot.img (rpi-make-boot-image → rpi-eeprom-digest → boot.sig).
3. Sign EEPROM WITHOUT program_pubkey (`update-pieeprom.sh -f -k KEY`), flash
   via rpiboot → signature checking active, key hash NOT yet in OTP. Reversible.
4. Validate: signed boot works, tampered boot.img rejected. Days of testing.

## Phase C (OTP burn, IRREVERSIBLE) — GATED

Only after Phase B is validated: set `program_pubkey=1` in the recovery
config, flash via rpiboot → SHA-256 of public key written to OTP, secure boot
permanently enforced. Requires the pre-burn checklist (EEPROM backup, key
backed up in 2 places, N clean dev-mode boots).

## Status

- 2026-08-17: rpiboot built (e50a7096). Board enters RPIBOOT mode via USB-C +
  power-button. Read-only state capture is the next action; no EEPROM/OTP
  writes performed yet.
