# Hardening & Secret Storage — Discussion (open items)

Captured Aug 18 2026 for further discussion. Concerns keeping the NV-index
authValue secret (whether the DUID or a burned custom secret) genuinely
confidential, and hardening the OS so an attacker cannot get code execution to
read it. NOT yet implemented — this is the design agenda.

## Context / the gap this addresses

The DUID lives in SoC OTP, NOT on the SD card, so it is confidential against
"stolen SD" and "stolen TPM module" attacks — it is only reachable by running
code on the device (root, or the firmware/RPIBOOT path). That is strictly
better than a secret embedded in the (SD-readable) U-Boot binary. The goal:
make "running code on the device" hard, so the DUID/secret stays confidential
within the in-scope threat model (remote + moderate physical access).

## Confidentiality checklist (what it takes)

1. **Secure boot — DONE.** Only our signed boot.img runs; attacker cannot boot
   their own OS to read OTP.
2. **Disable U-Boot interactive console + boot delay.** Closes the "interrupt
   U-Boot, `fdt print /chosen`" vector. No boot delay, no CLI; U-Boot is signed
   so it cannot be re-enabled. Also: DUID is NOT printed to serial by firmware
   or our code today — keep it so; strip `[MBOOT]` debug prints for production.
3. **Rootfs integrity — THE BIG GAP (currently open).** boot.img (kernel +
   U-Boot + DTB) is signed, but the ext4 rootfs (mmcblk0p2) is UNSIGNED and
   writable. Physical attacker can mount it, add a boot-time script to dump the
   DUID; secure boot won't notice (it only verifies boot.img). Until fixed, all
   other hardening is undermined. Fix: dm-verity (read-only, verified rootfs,
   root hash anchored in the signed boot chain) OR initramfs inside boot.img.
   See "Two-filesystem design" below.
4. **Lock down the OS.** Remove `debug-tweaks` (we currently have PASSWORDLESS
   ROOT). Drop dropbear or make it key-only. No interactive login in
   production. Restrict `/dev/vcio` (mailbox path to OTP).
5. **RPIBOOT-post-burn test — MUST settle empirically.** If an unsigned second
   stage still runs over USB after the burn, a physical attacker extracts the
   DUID via USB regardless of all Linux hardening. Deferred test.

Residual risk (thesis threat model): a vuln in a running service → root → DUID;
and hardware attacks (bus probing, glitching, decap) can extract OTP — both
out of scope. Within scope, the hardened design keeps the DUID confidential.

## Rafael's questions (to work through)

### Q1. How to burn a CUSTOM secret into OTP?

Two candidate OTP regions:

**(a) Customer OTP rows** — `nvmem_cust0` (32 bytes), currently all-zero and
writable. General-purpose. READABLE via `vcgencmd otp_dump` / nvmem sysfs (i.e.
same exposure as DUID: on-device code can read it).

**(b) Device private-key store — BETTER.** Tool: `usbboot/tools/rpi-otp-private-key`.
Pi 5 supports up to 16 words (64 bytes). CRITICAL PROPERTY from the tool docs:
*"These values are NOT visible via `vcgencmd otp_dump`."* This is a PROTECTED
keystore (the `nvmem_priv0` region), accessed only through a dedicated firmware
mailbox — not the general OTP dump path. Intended for an ECDSA P-256 private
key, but stores raw bytes.
- Write: `rpi-otp-private-key -w -y [-l <words>] [-o <offset>] <hexkey>`
- Read: `rpi-otp-private-key` (no args)
- OTP is write-once per bit (0→1 only); tool enforces new == (old OR new).
- IRREVERSIBLE, like all OTP.

Recommendation: if we burn a custom secret, use (b) — full 256-bit entropy of
our choosing, and NOT exposed by otp_dump. One more irreversible burn (optional;
the DUID route needs no extra burn but has lower entropy and is otp_dump-visible).

### Q2. Will that secret be visible to U-Boot? How?

Needs verification (see "Open technical questions"). The private-key store is
read via a VideoCore firmware **mailbox** property, NOT a memory-mapped
register. Findings so far:
- U-Boot (our xen-troops fork) has RPi mailbox/firmware infrastructure for
  clocks/board-info, but a grep found NO existing tag for reading the OTP
  private key. So U-Boot likely CANNOT read the private-key store today without
  us adding a mailbox call.
- By contrast, the DUID arrives "for free": firmware puts it in the device tree
  (`/chosen/rpi-duid`) which U-Boot already parses in RAM. No mailbox needed.
- Trade-off: DUID = zero extra U-Boot code but otp_dump-visible + modest
  entropy; custom private-key secret = strong + hidden from otp_dump but
  requires implementing a firmware mailbox read in U-Boot (extra C, and the
  mailbox tag must exist / be documented). NEEDS a spike to confirm feasibility.

### Q3. How to further secure the OS — two filesystems?

Rafael's proposal (sound, and standard practice): split into
- a **read-only, integrity-protected** rootfs holding all executables/config
  (verified via dm-verity; its root hash lives in the signed boot chain so
  tampering is detected/refused), and
- a **read/write data partition** for mutable state only (no executables), which
  is NOT trusted — treated as untrusted input, optionally encrypted (LUKS) with
  a key sealed to the TPM/OTP.

This is exactly the Yocto `read-only-rootfs` + dm-verity pattern. Effect: an
attacker cannot persist a boot-time payload in the executable FS (any change
breaks verity), and the writable FS carries no code that runs with privilege.
This is the real fix for checklist item #3. Yocto support:
`IMAGE_FEATURES += "read-only-rootfs"`, `dm-verity` via
`meta`/`wic` verity plugins or an initramfs that sets up the verity device
before pivoting root; root hash passed on the (measured, signed) kernel
cmdline / DTB.

## Open technical questions (spikes needed)

1. Does a firmware mailbox tag exist to read the private-key OTP store from
   U-Boot? If not, is there a documented tag we can implement? (blocks Q2 for
   option (b)).
2. RPIBOOT post-burn: does an unsigned second stage still execute? (blocks the
   whole "keep DUID/secret confidential" premise via USB).
3. dm-verity on this Yocto (Scarthgap) + meta-raspberrypi: cleanest integration
   (wic verity vs initramfs), and how to anchor the root hash in the signed
   boot.img so it is covered by secure boot.

## Decision pending

Anchor the NV authValue on: (A) the DUID (free in U-Boot, otp_dump-visible,
modest entropy) or (B) a custom secret burned to the private-key OTP store
(strong + otp_dump-hidden, needs U-Boot mailbox read). Resolve after spike #1.
