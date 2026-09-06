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
- Create the device's provisioning manifest (JSON): identities (DUID is a
  public id, recorded as-is; the secret is the TPM authValue, not the DUID),
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
- Create NV extend index 0x01C00000 (NT=Extend, SHA-256, clear_stclear).
  Policy: **PolicyAuthValue** (Option A) -- extend requires proving the index
  authValue via an HMAC policy session; POLICYWRITE blocks cleartext auth.
  authValue is a server-generated random secret (the "factory secret"),
  available to U-Boot at boot; NOT derived from DUID (see 3b/3c).
  Admin actions (undefine/reset the index) are separately gated by the OWNER
  hierarchy auth (locked to a random value held off-device) -- so "who may
  extend" (factory secret, in U-Boot) and "who may wipe" (owner auth, server)
  are already governed by different secrets WITHOUT needing PolicyOR.
- REJECTED alternative (Option B: PolicyOR(PolicyPCR, PolicyAuthValue)): the
  PolicyPCR branch is circular for boot-time extends -- binding extension to
  the measurement PCRs means a tampered boot cannot extend at all, leaving the
  index indistinguishable from "never booted"; binding to an earlier PCR adds
  no security since a hacked U-Boot reproduces that state (only secure boot
  stops hacked U-Boot, per 3b). Validated design is Option A.
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

HYPOTHESIS — ✅ **VALIDATED 2026-09-06 (H6). CHANNEL IS LOCKED.** Full method,
logs and caveats: `provisioning/h6-duid-usb-test/RESULTS.md`.

Identical command / host / payload against two boards differing ONLY in the OTP
burn, `rpiboot -v -d mass-storage-gadget64` (an UNSIGNED, host-supplied second
stage — exactly what a physical attacker would use):

| | 16 GB UNBURNED (control) | 1 GB BURNED |
|---|---|---|
| bootcode5.bin executed | YES | **NO** |
| file requests from device | 21 | **0** |
| final USB ID | 0a5c:0104 (gadget) | 0a5c:2712 (still ROM) |
| USB block device | sda 29.5 GB | **none** |
| rpiboot exit | 0 | 124 (timeout) |

Decisive lines from the burned board:
```
Sending bootcode.bin
libusb_bulk_transfer sent 78332 bytes; returned 0   <- ROM ACCEPTED the bytes
Successful read 4 bytes
Waiting for BCM2835/6/7/2711/2712...                <- reset; did NOT execute
Sending bootcode.bin
Failed control transfer (-7,24)                     <- loops indefinitely
```
So the ROM answers the question Rafael raised on Aug 18 ("does it reject at LOAD
or only refuse to EXECUTE?"): it **accepts the transfer and then refuses to
execute**, resetting instead. The board never reaches the file-server phase.

⇒ The RPIBOOT arbitrary-code door is CLOSED post-burn. An attacker with physical
USB access cannot run code on the provisioned board, hence cannot use that
channel to read OTP / report the DUID.

CAVEAT (do not overclaim): this proves unsigned CODE cannot run. It does not
prove the absence of an undocumented ROM-level command that discloses OTP without
executing a second stage — the host never issues such a command, so the 244 KB
capture (no FACTORY_UUID, no DUID digits) is a lower bound, not a proof.

METHODOLOGICAL NOTE: `mass-storage-gadget64` does NOT emit FACTORY_UUID even on
an UNBURNED board — DUID metadata comes only from the EEPROM recovery flow (both
JSONs in provisioning/baseline/ are from EEPROM flashes). So "no FACTORY_UUID on
the wire" is NOT the load-bearing evidence; the REFUSAL TO EXECUTE is. The first
run of this experiment wrongly treated absent metadata as meaningful — the
positive control is what caught it. Always run the control first.

DEEPER POINT (Rafael, Aug 18): even if second-stage EXECUTION is locked to our
key post-burn, that is a different ROM function from the ROM's own USB PROTOCOL
HANDLERS. The RPIBOOT USB command set is UNDOCUMENTED and partly in immutable
mask ROM. OTP gates code AUTHORIZATION, not ROM message handlers — so a
hypothetical ROM-level "read OTP / get device info" command would be ungated by
any burn. We therefore CANNOT prove the DUID is confidential over USB, before
OR after burn (cannot prove a negative over an undocumented API; usbboot source
only enumerates the commands IT uses — a lower bound, not a ceiling).

CONCLUSION — REVISED 2026-09-06 (Rafael). The previous wording said "treat the
DUID and ALL OTP as physically extractable over USB, permanently". That is
RETRACTED: it overstates what is known, and taken literally it would invalidate
the proposed solution (whose board-binding rests on post-provisioning DUID
confidentiality). What the evidence actually supports:

- PRE-BURN: the DUID *is* disclosed over USB. Verified directly — our own
  provisioning run's rpiboot metadata JSON contains FACTORY_UUID = the DUID.
  This is fine: pre-burn/factory is the TRUSTED provisioning environment.
- POST-BURN: the DOCUMENTED disclosure path is gated by the customer key. DUID
  reporting requires EXECUTING a second stage that chooses to read OTP and emit
  it; post-burn the ROM requires that second stage to be counter-signed with the
  customer key. So an attacker without the private key should get nothing.
- The honest residual is narrow and specific: we cannot PROVE the absence of an
  undocumented ROM-level command, because the ROM is immutable and the protocol
  is only partly documented (usbboot source enumerates the commands IT issues —
  a lower bound, not a ceiling). This is a "not proven", NOT a demonstrated leak.

=> State it as: post-provisioning, the DUID's confidentiality rests on the boot
chain (secure boot + signed second stage) and OS hardening, exactly like any
OTP-held key on a SoC without a TEE. Quantify the residual with the H6 experiment
below rather than assuming the worst case.

Note the DUID and the TPM NV authValue are NOT the same asset: the authValue
lives in TPM shielded storage on a separate chip/bus that no BCM2712 ROM command
can reach. Today the authValue is DERIVED from the DUID, so DUID confidentiality
still matters; an anchor in the OTP private-key store (hidden from otp_dump)
would decouple them (optional strengthening, TODO.md B1).

### H6 EXPERIMENT PLAN (post-burn, designed 2026-09-06) — raise confidence

Board cceddb12-0af4f481 is now BURNED, so the Aug-18 test can finally be redone
under enforcement. Wire format to look for (from usbboot main.c:780-810): the
device sends metadata as a MESSAGE FILENAME of the form
    *FACTORY_UUID*<hex words separated by "_">
which the host c40-decodes (decode_duid.c) into the printable DUID. So the
literal ASCII "FACTORY_UUID" on the bus is a reliable leak detector.

- **E0 POSITIVE CONTROL (do FIRST, else a null result proves nothing):** run the
  capture against the UNBURNED 16 GB board. FACTORY_UUID *must* appear. This
  validates that the capture pipeline would see a leak if one occurred.
- **E1 unsigned second stage (no flash, lowest risk):**
  `sudo ./rpiboot -d mass-storage-gadget64` on the burned board.
  REFUSED => the arbitrary-code path is closed (attacker cannot run code to read
  OTP). RUNS => critical finding, channel open.
- **E2 bad-signature EEPROM, post-burn:** repeat the Aug-18 corrupt-pieeprom.sig
  test (aborts before flashing; that is why it is low risk) with `-j metadata`.
  Expect: no metadata JSON AND no FACTORY_UUID in the capture.
- **E3 wrong-key-signed image:** sign an EEPROM with a DIFFERENT RSA key. This is
  the closest analogue to a real attacker (they can sign, just not with OUR key).
  Expect rejection with no DUID emitted.
- **E4 USB capture across all of the above** — the methodological upgrade:
  `sudo modprobe usbmon`, then capture the Pi's bus
  (`sudo cat /sys/kernel/debug/usb/usbmon/<bus>u > cap.txt`) and grep for
  "FACTORY_UUID" and for the decoded DUID digits. This shows what the board
  actually SENT, rather than what rpiboot chose to write to a file.

Scope of the claim these support (state precisely, do not overclaim): they show
the ROM does not volunteer the DUID during the documented handshake, and that
unsigned code cannot run to fetch it. They cannot exclude an undocumented command
that the host never issues. That is a much narrower residual than "assume it
always leaks", and it is empirical rather than assumed.

SOURCE-CODE EVIDENCE (usbboot main.c / decode_duid.c, examined Aug 18 2026):
- The rpiboot USB protocol after the boot handshake is a passive 3-command FILE
  SERVER, and the commands are issued BY THE DEVICE, not the host:
  0=GetFileSize, 1=ReadFile, 2=Done (main.c:848,889,918,966). The host cannot
  ask the ROM for anything; it only answers file requests from the running
  second stage.
- There is NO host-initiated "read OTP" / "get DUID" command in the protocol.
- Precise mechanism: the second-stage firmware RUNS ON THE BOARD during
  flashing (RPIBOOT = ROM loads+executes host-supplied code with full hardware
  access). That on-board code reads the raw OTP and emits it as `*`-prefixed
  METADATA MESSAGES over the same file-server channel (main.c:867 treats a
  filename starting with '*' as a metadata key:value, not a file request). The
  host's rpiboot then c40-DECODES the raw DUID (duid_decode_c40, main.c:798)
  into FACTORY_UUID and writes the JSON. So DUID disclosure requires EXECUTING
  a second stage that chooses to read OTP and report it — it is NOT a host-side
  query of the ROM.
- Implication: post-burn, only a customer-counter-signed second stage runs, so
  the DOCUMENTED metadata-extraction path is gated by our key.
- Caveat kept: this is a LOWER BOUND (rpiboot only calls the commands it knows).
  A hidden ROM-level vendor control-transfer answered before any second stage
  cannot be excluded from source. Net position unchanged: assume DUID/OTP may be
  USB-reachable; it does not matter because the only secret is the TPM-shielded
  NV authValue, not the DUID.

EXPERIMENT (Aug 18 2026) — bad-signature EEPROM does NOT leak DUID:
Fed rpiboot an EEPROM image with a corrupted pieeprom.sig (pieeprom.bin left
good, no brick risk). Result on the unburned board:
- The on-board second stage read pieeprom.sig, found it invalid, and ABORTED
  BEFORE reading pieeprom.bin (never flashed) AND before reading OTP.
- NO metadata JSON was written -> FACTORY_UUID / DUID NOT reported.
Comparison: the successful (good-sig) flash DID read pieeprom.bin and DID emit
the DUID metadata. => the DUID report is gated behind successful signature
validation; a bad-signature firmware is rejected before any OTP read/report.
This is also a firmware-level tamper-rejection result (complements the boot.img
tamper test). Caveat: unburned board, so bootcode5.bin ran freely (RPi-signed);
what was rejected here is the EEPROM-image signature. Post-burn adds an EARLIER
gate (bootcode5/recovery.bin must be customer-counter-signed) — to be validated
post-burn.

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
