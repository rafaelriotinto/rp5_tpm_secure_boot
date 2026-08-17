# Device Provisioning Design (RPi5 secure + measured boot)

*Specification for the automated provisioning flow. Provisioning runs in a
controlled ("secure") environment: trusted host, isolated network, fresh
validated image. Goal: take a factory-fresh board to a fully provisioned,
attestable, secure-boot-enforcing device, producing an auditable record.*

## 1. Device identities and their roles

Verified on hardware (Aug 2026, two boards):

| Identifier | Where stored | Exposure | Role in this design |
|---|---|---|---|
| SoC serial (64-bit, e.g. `cceddb120af4f481`) | OTP | PUBLIC: firmware boot banner, DT `/chosen/rpi-serial64`, `/serial-number`, and the Ethernet MAC is derived from it (broadcast on LAN) | **Device unique ID** in the attestation database |
| DUID (`/chosen/rpi-duid`, e.g. `0000911045808726`) | OTP | Not in the boot log; readable from the DT by root on-device | **HMAC key material** for TPM NV authValue derivation |
| Board revision (`a04171`, bit-packed: memory/manufacturer/type/rev) | OTP | public | recorded in provisioning manifest |
| Customer key hash (OTP rows) | OTP | public (hash only) | secure boot root of trust (written in step 6) |

HMAC key derivation (per February design, refined):
`nv_auth = HMAC-SHA256(key=DUID, msg="rp5-nv-auth" || soc_serial)`.
Caveat recorded for the threat model: the DUID is readable by root on the
running device; it protects against remote/parted attackers (stolen SD card,
cloned image, other boards) but not against an attacker with root on the live
device. Optionally strengthen with a server-side factory secret mixed into the
HMAC (decision pending).

## 2. Provisioning stages

Scripted under `provisioning/` (host side + on-device helpers), executed in
order; each stage writes its results into the provisioning manifest.

**Stage 0 — Preconditions & audit basis**
- Trusted host, isolated network, freshly flashed validated image (record its
  build hash / BUILD.md revision), serial console attached.
- Record EEPROM/bootloader version; **EEPROM configuration backup** (recovery
  basis while still reversible).

**Stage 1 — Identity harvest**
- Read SoC serial, DUID, board revision (via SSH/serial from DT).
- Create the device's provisioning manifest (JSON): identities (DUID never
  stored in cleartext in the DB — store HMAC-derived check value only),
  timestamps, operator, image build id.

**Stage 2 — Key material (host side, offline)**
- Generate (or reuse project) RSA-2048 signing keypair (openssl); private key
  stays on the provisioning host, never on the device.
- Compute SHA-256 of the public key (the future OTP value).

**Stage 3 — boot.img build & sign**
- Pack boot.img (inner config.txt, U-Boot, DTB, overlays, Image) —
  reproducible via the Yocto recipe; record its SHA-256 in the manifest.
- Sign: `boot.sig` (digest + RSA signature, rpi-eeprom tooling).

**Stage 4 — Signed-boot development mode (reversible rehearsal)**
- EEPROM config: enable signature verification with the public key in EEPROM
  (no OTP write). Boot, verify chain works, verify tampered boot.img is
  rejected. Everything still reversible.

**Stage 5 — TPM provisioning**
- `tpm2_clear` (explicit operator confirmation), set hierarchy auth values.
- Create EK + AK (attestation identity); export AK public → enrollment record
  for the attestation server.
- Create NV extend index 0x01C00000 (NT=Extend, SHA-256) with authValue =
  derived nv_auth; policy: authValue-gated extend (PolicyAuthValue), read
  without auth (or per policy decision).
- Record dictionary-attack lockout parameters.

**Stage 6 — OTP programming (IRREVERSIBLE — gated)**
- Interactive triple-confirmation + checklist (EEPROM backup exists, dev-mode
  validation passed N boots, key backed up in 2 locations).
- Write customer key hash to OTP; enable secure boot enforcement.
- Verify: unsigned boot refused; signed boot works.

**Stage 7 — Golden values capture**
- Boot final configuration; read PCRs 0, 1, 8, 9 and the NV index value.
- Store in the attestation database (per-device: PCR0/PCR1 are board-specific;
  PCR8/9 shared per image build — derivable from the build system, verified on
  hardware Aug 2026).
- Manifest completed and archived (optionally signed by provisioning key).

**Stage 8 — Acceptance test**
- Full attestation round against the monitoring server (quote + verify).
- One tamper test (modified cmdline or kernel) → server must flag.

## 3. Provisioning record (manifest) fields

device_serial, board_revision, duid_check (HMAC of DUID, not raw), eeprom
version, image build id + BUILD.md git rev, boot.img sha256, pubkey sha256
(OTP value), AK public key, NV index + attributes, golden PCR set, NV golden
value, lockout params, operator, dates per stage, validation results.

## 4. Open decisions

1. Mix a server-side factory secret into nv_auth (stronger against on-device
   root) — or accept DUID-only (simpler, matches Feb design)?
2. NV index read policy: open read vs authValue-gated read.
3. OTP stage on the 1 GB sacrificial board only, or eventually also the 16 GB
   dev board? (current plan: sacrificial only)
4. Manifest storage/signing location.
5. Whether AK enrollment requires the EK certificate chain (full remote
   attestation enrollment) or direct AK-pub trust (lab simplification).

## 5. Status

- 2026-08-17: doc created. Identity roles verified on both boards (uboot.env
  identity-spoofing observation reinforced why identities must come from
  OTP-backed DT values, not U-Boot env). Scripts not started; secure-boot
  level-2 (boot.img) validation is the current work item and a prerequisite
  for stages 3-4.
