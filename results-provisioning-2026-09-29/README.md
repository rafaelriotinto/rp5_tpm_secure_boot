# First-time provisioning from a cleared TPM (control board, 2026-09-29)

Thesis Section 6.8. Files: 01-06 below; scripts: build-factory-test-uboot.sh, uboot-clear.py.

- The control board (192.168.10.124, OTP not programmed) already had a firmware key, so the real
  factory U-Boot (guard) refuses it. A TEST factory U-Boot was built with `build-factory-test-uboot.sh`:
  factory settings (no ARB, no key lock), no guard, BOOTDELAY=3. The test release was signed with a
  throwaway key, never the owner key (the demonstration board would refuse it).
- TPM cleared from the U-Boot console through the platform hierarchy (`uboot-clear.py`):
  `tpm2 init; tpm2 startup TPM2_SU_CLEAR; tpm2 clear TPM2_RH_PLATFORM`. Next boot:
  `NV read_public failed 0x18b`; status `counter: null` (01).
- `rp5.py provision-fwkey` took the first-time path (`reprovisioned: false`): EK, new AK (differs
  from the pre-clear one), both PolicySigned indices, first firmware-signed increment, hierarchy
  auths (02). Firmware key Name unchanged (key in OTP, not regenerated).
- The new counter started at **13**, not 1: a new NV counter starts at the highest value any counter
  has held on the TPM, and this survives TPM2_Clear -> a clear cannot lower the anti-rollback floor.
- `rp5.py update` to r22: trial left the counter at 13, all checks passed; committed boot
  `[ARB] counter advanced to 22 (committed)`, NV commit OK, key locked 0x1f01; final attestation with
  the restart requirement PASSED (resetCount 5 -> 6) (05, 06).
- Server gap found (TODO): TPM2_Clear resets resetCount; provisioning does not reset the verifier's
  per-board `attest-state.json`, so the first trial was rejected as stale (166 -> 1, run 03); with the
  state removed, the first round only records a baseline (run 04). Both failed safe (no commit,
  fallback). Fix: enrollment resets the state and seeds the baseline.
