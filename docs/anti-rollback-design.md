# Anti-Rollback (Version Downgrade Prevention) — Design

Prevent an attacker from replaying an OLD, still-validly-signed `boot.img`
(U-Boot + kernel + rootfs reference) that contains a known vulnerability.
Design agreed Aug 19 2026; **implemented 2026-09-13** (see "As implemented").

## Problem: the platform protects its firmware, not our payload

Verified against the RPi tooling:

- **BL1 (SoC ROM, immutable)** verifies BL2.
- **BL2 (EEPROM firmware)** HAS a coarse anti-rollback for ITSELF:
  `BOOTLOADER_SECURE_BOOT_MIN_VERSION` (a timestamp in `update-pieeprom.sh`,
  and the documented "cannot downgrade to a bootloader that doesn't support
  secure boot"). This protects the EEPROM firmware version only.
- **boot.img has NO anti-rollback.** BL2 verifies the customer signature and
  boots any customer-signed `boot.img`, old or new. So an attacker can replay
  an older signed SD image with a known bug -- a rollback/replay attack.

The fix must live in BL3 (U-Boot) or later, because nothing before it version
-checks the payload.

## Mechanism: TPM NV monotonic counter, enforced by (signed) U-Boot

Use a TPM 2.0 NV **counter** index (`TPMA_NV_COUNTER`) -- monotonic, can only
increase, persists across reboots.

- Each release has a monotonic version `V` (a build epoch: 1, 2, 3, ...).
  U-Boot carries `MY_VERSION` compiled in (a Kconfig/const).
- The NV counter holds `C` = the highest version that has ever run.
- Early in U-Boot boot:
  1. Read `C` (TPM2_NV_Read -- already have tpm2_nv_read_value).
  2. `MY_VERSION < C`  -> ROLLBACK -> HALT (refuse to boot).
  3. `MY_VERSION > C`  -> increment the counter up to `MY_VERSION` (authorized
     TPM2_NV_Increment), then boot.
  4. `MY_VERSION == C` -> boot.

Authorization for the increment reuses the measured-boot pattern: a policy
session (PolicyAuthValue) proving the DUID-derived secret. Reading the counter
is open. So only a legitimate (secret-deriving) U-Boot advances the counter;
an attacker without the secret cannot bump it (no DoS via arbitrary increment).

## Why a self-check is sound here

The check is enforced by U-Boot on itself, which is only trustworthy because
SECURE BOOT prevents running a MODIFIED U-Boot. An attacker can only replay an
OLD, LEGITIMATE, signed U-Boot -- and that old U-Boot contains ITS OWN copy of
the check, reads the counter, sees `MY_VERSION(old) < C`, and halts itself.
Rollback to any check-enabled version is self-defeating.

## One counter protects the whole payload

U-Boot, the kernel, and (eventually) the dm-verity root hash all live inside
the single signed `boot.img`. So ONE version number on the boot.img transitively
covers U-Boot + kernel + rootfs. No separate per-component counters needed.

## Limitations (state honestly in the thesis)

1. **Genesis problem.** Cannot protect against rollback to a version that
   predates the check (it has no check, so it boots freely). Mitigation: ship
   the check in the FIRST production image; treat pre-check images as revoked.
   Fundamental to all anti-rollback, not specific to us.
2. **tpm2_clear resets the counter** -- and clearing is currently OPEN on our
   device (no lockout auth, platform hierarchy not disabled). An attacker who
   clears the TPM resets `C` to 0 -> any old version boots. HARD DEPENDENCY:
   lock down tpm2_clear (set lockout auth; and/or make the counter
   platform-created so it survives an owner clear). Ties to the hardening list.
3. **TPM swap/relocation.** A fresh TPM has `C = 0`. Defense: U-Boot must FAIL
   CLOSED -- if the counter index is missing/unreadable, HALT (assume
   tampering). With the DUID-derived auth, a fresh TPM on this board has no
   provisioned index -> TPM removal -> brick = fail-secure.
4. **NV_Increment is +1 only** -- loop to catch up across skipped versions.

## Implementation plan (reuses ~80% of the measured-boot work)

Already have: policy/HMAC session machinery, hmac_sha256, tpm2_nv_read_value,
DUID-derived secret, tpm2_start_auth_session / policy_auth_value /
flush_context.

To add:
- **TPM2_NV_Increment** (CC 0x0134) in lib/tpm-v2.c (~35 lines; like nv_extend
  but no data parameter -- cpHash over CC || authName || nvName only).
- Provisioning: define an NV COUNTER index (e.g. 0x01C00001, `nt=counter`,
  policywrite, PolicyAuthValue, same DUID-derived authValue). Extend
  provision-nv-index.sh.
- U-Boot: `CONFIG_ANTIROLLBACK_VERSION` (compiled-in `MY_VERSION`) + the
  read/compare/increment/halt logic, run early in boot (before booti). Fail
  closed on any TPM error or missing index.
- Release process: bump `CONFIG_ANTIROLLBACK_VERSION` whenever a security fix
  should invalidate older images.


## As implemented (2026-09-13)

- **Version**: `CONFIG_ANTIROLLBACK_VERSION`, a plain unsigned integer bumped
  by one per release (1, 2, 3 ...), compiled into U-Boot and therefore inside
  the signed `boot.img`. The same number is declared in the release manifest
  (informational). A build is a release; PCR0 already changes per build.
- **Counter**: TPM NV index `0x01800002`, `nt=counter` (64-bit),
  `policywrite|ppread|ownerread|authread|no_da`, NO `clear_stclear`.
  Provisioned by `provisioning/anti-rollback/provision-counter.sh` (defined
  under the owner hierarchy with the owner auth, incremented once so it is
  readable; starts at 1). Increment authorised by a PolicyAuthValue session
  with `SHA256("rp5-nv-counter-v1" || DUID)` -- a separate label from the
  measured-boot index's secret, same derivation, so U-Boot derives it at boot.
  Reads use the empty platform auth (`ppread`), like the extend index.
- **Check** (`antirollback_check()` in `boot/bootm.c`, right after
  `tcg2_measurement_init`, before anything of the release is measured or
  loaded): read counter; `version < counter` -> refuse; `==` -> boot;
  `>` -> if the firmware's tryboot flag is 0, increment up to `version`
  (`TPM2_NV_Increment`, new in `lib/tpm-v2.c`), read back, boot.
- **A/B rule**: on a **tryboot the counter is never advanced**. Validated on
  hardware (E15): trials left it at 1 and 4, the first committed boots took
  it to 4 and 5. The rule rests on the firmware reporting the tryboot flag
  faithfully in `/chosen/bootloader/tryboot`; EEPROM releases before
  2024-04-17 lost the flag in secure-boot mode ("Fix TRYBOOT flag in
  secure-boot mode", rpi-eeprom release notes), which would make a trial
  look committed and advance the counter early. The agent's first health
  check is therefore `tryboot == 1`; if not, it must not commit. Otherwise a
  new release that fails its health check would leave the committed (older)
  pair unbootable. The counter advances on the first plain boot after commit.
- **Refusal = reset, not hang**: on a tryboot the firmware then boots the
  committed pair by itself (the one-shot flag is consumed); on a committed
  pair a reset loop denies the old release like a halt would, without a
  remote power-cycle. Missing counter, no DUID, any TPM error: same path.
- **TPM clear / swap**: index gone -> refuse (fail closed). An attacker who
  clears the TPM and defines a fresh counter still cannot satisfy the
  increment policy without the DUID-derived secret, so this rests on the
  same load-bearing dependency as everything else (secure boot + DUID
  confidentiality). A cleared TPM also empties the measured-boot index, so
  the server sees it at the next attested reboot.

## Thesis value

Anti-rollback for the customer OS payload on a platform (RPi5) that provides it
only for the bootloader firmware, enforced by secure-boot-protected U-Boot via a
TPM monotonic counter. Closes the replay-old-signed-image gap; a distinct,
well-motivated contribution alongside secure boot + measured boot.

## Status

- 2026-08-19: design documented. Depends on: tpm2_clear lockdown (hardening).
  Implement after / alongside OS hardening (#3).
- 2026-09-13: implemented and validated on hardware (experimental-results.md E15): trial boot
  leaves the counter, committed boot advances it (1→4→5), a signed version-3 image is refused
  and the firmware falls back to the committed pair (resetCount +2).
