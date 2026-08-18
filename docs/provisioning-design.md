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
| DUID (`/chosen/rpi-duid`, e.g. `0000911045808726`) | OTP | PUBLIC: readable by on-device root AND via rpiboot metadata (FACTORY_UUID) on unprovisioned boards — see 3c | Secondary device ID / derivation salt ONLY (NOT a secret — see 3b/3c) |
| Board revision (`a04171`, bit-packed: memory/manufacturer/type/rev) | OTP | public | recorded in provisioning manifest |
| Customer key hash (OTP rows) | OTP | public (hash only) | secure boot root of trust (written in step 6) |

NV authValue source (SUPERSEDES the February DUID-HMAC idea — see 3b/3c):
the DUID is PUBLIC and cannot anchor security. The NV index authValue is a
random secret generated on and held only by the provisioning/attestation
server, stored in TPM shielded storage on the device (never on its
filesystem, never derived from OTP). Boot-time extends use a PolicyPCR leg
(no secret needed); admin ops use the server-held authValue.

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
- Create NV extend index 0x01C00000 (NT=Extend, SHA-256). Policy:
  PolicyOR(PolicyPCR for boot-time extends, server-held PolicyAuthValue for
  admin/redefine). authValue is a server-generated random secret, NOT derived
  from DUID (see 3b/3c).
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

device_serial, board_revision, duid (public id), eeprom
version, image build id + BUILD.md git rev, boot.img sha256, pubkey sha256
(OTP value), AK public key, NV index + attributes, golden PCR set, NV golden
value, lockout params, operator, dates per stage, validation results.

## 3b. NV authorization threat analysis (resolved, Aug 17 2026) — THESIS-CRITICAL

Governing principle: **measured boot has no integrity of its own — whoever
controls the extend path controls the measurements.** A hacked U-Boot can
extend the NV index (and PCRs 0/1/8/9) with any chosen values, including
replaying the real board's public identity (serial/DUID from the DTB), and
produce a "clean" attestation while running malicious software. Neither a
PolicyPCR condition nor an authValue prevents this, because the malicious
extender either satisfies the policy legitimately (public PCR state is
replayable) or already holds the secret.

Consequences:
- The ONLY thing preventing a hacked U-Boot from running is **secure boot**
  (OTP-fused signed-U-Boot enforcement). Measured boot's integrity is entirely
  contingent on it.
- Phase binding (U-Boot capping PCRs 0-7 with EV_SEPARATOR before OS handoff)
  protects only WITHIN one honest boot — it does not stop an attacker who
  controls U-Boot from extending before the separators fire.
- A discrete, external SPI TPM **cannot authenticate the platform it is
  attached to**. Relocating the TPM to an attacker-controlled (unfused) board
  lets a hacked U-Boot forge all measurements; the stolen AK still signs a
  clean-looking quote. This is the classic TPM relocation / bus-interposer
  attack, aggravated here by an unencrypted, bit-banged SPI bus and the
  absence of any on-device root-unreachable secret store (OTP is root-readable
  via `vcgencmd otp_dump`; the boot chain has no TrustZone secure world).

Scoping statement for the thesis threat model:
**The proposed mechanism defends against a SOFTWARE adversary on an intact,
secure-boot-enforced device: unsigned U-Boot cannot run, so runtime
measurements cannot be forged. It does NOT withstand an adversary who obtains
the extend-path secret or control — via root access, memory/SPI bus probing,
TPM relocation, or equivalent. This is intrinsic to a discrete external TPM
with no authenticated platform binding, not a defect of the implementation;
mitigation would require an integrated/firmware TPM or an authenticated TPM
bus with a platform-bound secret, neither available on this hardware.**

What the server-held authValue realistically buys (narrow but real): it stops
on-device root from administratively resetting/redefining the NV index (which
would let it hide history by starting clean). It does NOT make boot-time
extends unforgeable against a platform-breach adversary.

### 3c. RPIBOOT disclosure (added Aug 18 2026)

Observed from our own provisioning run: the rpiboot metadata JSON contains
FACTORY_UUID = the DUID (plus serial, boardrev, all MACs). Pre-OTP-burn,
RPIBOOT executes ANY host-supplied second stage -> arbitrary code execution
with full hardware access for anyone with physical USB access; the DUID (and
all OTP) is disclosed. This CONFIRMS the 3b decision: DUID is a public
identifier / derivation salt, never a security anchor. Secrets live only in
TPM shielded storage (server-held authValue) or off-device (RSA private key)
-- neither reachable via RPIBOOT.

HYPOTHESIS (NOT yet validated — do not state as fact): post-OTP-burn the ROM
may require customer-counter-signing for the USB/RPIBOOT second stage too,
which would close the RPIBOOT arbitrary-code door. BUT rpiboot is the most
primitive BL1/ROM function; it is unclear whether the ROM rejects an unsigned
USB payload at LOAD or only refuses to EXECUTE it, and the docs only state that
`program_pubkey=1` disables recovery.bin from SD/EMMC (not explicitly the USB
path). MUST validate empirically after the burn:
  - enter RPIBOOT, run `rpiboot -d mass-storage-gadget64` (UNSIGNED 2nd stage);
  - if it refuses to run / no MSD device appears -> channel locked (hardening
    confirmed);
  - if the gadget still boots and OTP is dumpable -> channel NOT locked; the
    DUID/OTP remain physically extractable even post-burn. Report whichever
    actually happens. Rafael's point (Aug 18): rpiboot is BL1-managed and may
    still execute regardless of OTP.

DEEPER POINT (Rafael, Aug 18): even if second-stage EXECUTION is locked to our
key post-burn, that is a different ROM function from the ROM's own USB PROTOCOL
HANDLERS. The RPIBOOT USB command set is UNDOCUMENTED and partly in immutable
mask ROM. OTP gates code AUTHORIZATION, not ROM message handlers — so a
hypothetical ROM-level "read OTP / get device info" command would be ungated by
any burn. We therefore CANNOT prove the DUID is confidential over USB, before
OR after burn (cannot prove a negative over an undocumented API; usbboot source
only enumerates the commands IT uses — a lower bound, not a ceiling).

CONCLUSION (thesis): treat the DUID and ALL OTP as physically extractable over
USB, permanently. This does NOT harm the design because the only true secret,
the TPM NV authValue, lives in TPM SHIELDED STORAGE on a separate chip/bus that
no BCM2712 ROM command can reach. The architecture contains the unknowable USB
surface by never placing a secret anywhere the ROM can address.

SOURCE-CODE EVIDENCE (usbboot main.c / decode_duid.c, examined Aug 18 2026):
- The rpiboot USB protocol after the boot handshake is a passive 3-command FILE
  SERVER, and the commands are issued BY THE DEVICE, not the host:
  0=GetFileSize, 1=ReadFile, 2=Done (main.c:848,889,918,966). The host cannot
  ask the ROM for anything; it only answers file requests from the running
  second stage.
- There is NO host-initiated "read OTP" / "get DUID" command in the protocol.
- The DUID (FACTORY_UUID) reaches the host because the SECOND-STAGE CODE WE FED
  the board computes it (decode_duid.c is a c40 decoder) and writes it into a
  metadata FILE returned via the same ReadFile path. DUID disclosure therefore
  depends on EXECUTING a second stage that chooses to report it.
- Implication: post-burn, only a customer-counter-signed second stage runs, so
  the DOCUMENTED metadata-extraction path is gated by our key.
- Caveat kept: this is a LOWER BOUND (rpiboot only calls the commands it knows).
  A hidden ROM-level vendor control-transfer answered before any second stage
  cannot be excluded from source. Net position unchanged: assume DUID/OTP may be
  USB-reachable; it does not matter because the only secret is the TPM-shielded
  NV authValue, not the DUID.

## 4. Open decisions

1. ~~Mix a server-side factory secret into nv_auth?~~ RESOLVED (see 3b):
   NV-extend justified on durability + admin-lifecycle-control grounds, not on
   "resists a moved TPM". Admin ops gated by server-held authValue; DUID
   demoted to device-ID/derivation salt, not a security anchor. Relocation
   limitation stated openly in the threat model.
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
