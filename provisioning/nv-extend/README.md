# Measured Boot via TPM NV Extend Index

Userspace prototype + reference for the measured-boot mechanism. This validates
the design on real hardware (tpm2-tools) and defines the exact TPM protocol the
U-Boot C implementation must replicate.

## Why an NV extend index (not a PCR)

Plain `TPM2_PCR_Extend` lets *anyone* with bus access extend a PCR — there is
no per-PCR secret. The goal here is that only an authorized party can add
measurements. A **NV extend index** gives PCR-like accumulation
(`NV_new = SHA256(NV_old || data)`) but is a normal addressable entity with its
**own authorization policy**, so writes can be gated by proving a secret via an
HMAC session. See thesis background (TPM 2.0 NV storage + Enhanced Authorization).

## Design (validated 2026-08-18, RPi5 + SLB9670)

Index `0x01800000`, 32 bytes, attributes
`nt=extend | policywrite | authread | ownerread | no_da | clear_stclear`:
- `nt=extend` — value only updatable via `NV_Extend`.
- `policywrite` — writing requires a **policy session** (blocks cleartext auth).
- `clear_stclear` — value resets to 0 each power cycle (PCR-like), while the
  authValue/policy persist permanently.
- authPolicy = `SHA256(TPM2_CC_PolicyAuthValue)` — the policy session must run
  `PolicyAuthValue`, i.e. prove the index authValue (the *factory secret*) via
  HMAC. The secret never crosses the bus in cleartext.

Provisioning (one-time): `provision-nv-index.sh`.
Per-boot extend + tests: `demo-extend.sh`.

## Results (hardware)

- Extend semantics verified: NV value = `SHA256(0^32 || data)` where `data` is
  the component digest passed directly (the TPM does NOT re-hash it — U-Boot
  must pass the already-computed component digest as the NV_Extend data).
- Correct-secret extend: accepted.
- Wrong-secret extend: rejected (`0x9A2` authorization failure).
- Cleartext-password extend: rejected (`0x12F`; POLICYWRITE forces HMAC session).
- Failed attempts leave the value unchanged.

Example NV name (needed by U-Boot for cpHash):
`000ba2421ed1108417fdf03b8ad03ff8b724ec78c6c622dfbea98609d350c6cd9630`
(the name is `nameAlg || SHA256(TPMS_NV_PUBLIC)` and changes if the index is
redefined — U-Boot recomputes or is provisioned with it).

## Protocol U-Boot must implement (lib/tpm-v2.c)

Per component, every boot:
```
TPM2_StartAuthSession(TPM_SE_POLICY)     -> policySession, nonceTPM
TPM2_PolicyAuthValue(policySession)
TPM2_NV_Extend(index=0x01800000, data=SHA256(component),
    session auth = HMAC-SHA256(factory_secret,
                     cpHash || nonceNewer || nonceOlder || sessionAttrs))
    where cpHash = SHA256(CC_NV_Extend || nvIndexName || nvIndexName || data)
TPM2_FlushContext(policySession)
```
Missing U-Boot pieces: StartAuthSession, PolicyAuthValue, NV_Extend,
FlushContext, and hmac_sha256 (only sha1_hmac exists). See docker CLAUDE.md /
thesis Chapter 4.

## Threat-model scope (see docs/provisioning-design.md 3b/3c)

The factory secret gating the extend must be available to U-Boot at boot, so it
lives in the (secure-boot-signed but SD-readable) U-Boot image. This defeats an
attacker who steals ONLY the TPM module (they lack the secret) and any
remote/software attacker, but not one who reads the SD or probes the bus. The
mechanism raises the bar and enforces authorized-only extension; it is not an
absolute defense against a full-platform physical compromise.

## U-Boot C implementation — VALIDATED ON HARDWARE (2026-08-18)

The protocol above is now implemented in raw C in the U-Boot fork
(commit 589f1443e7, lib/tpm-v2.c + include/tpm-v2.h + cmd/tpm-v2.c):
hmac_sha256, tpm2_start_auth_session, tpm2_policy_auth_value,
tpm2_nv_read_public, tpm2_nv_extend, tpm2_flush_context, plus a
`tpm2 nvextend` console command for testing.

Validation: a signed boot.img running this U-Boot extended 32 bytes of 0xAB
into the (zeroed, clear_stclear) NV index. The TPM ACCEPTED the session HMAC
(secret proven, never sent on the bus), and Linux read back
`debb3e7acfff6dd18d501042273629f0b79cb206bb8c24f59f62ddb80849403b`
= SHA256(0^32 || 0xAB*32), matching the tpm2-tools reference bit for bit.
So the cpHash and session-authHMAC computations are correct.

NOTE on the NV index handle: the U-Boot functions follow the existing
lib/tpm-v2.c convention where `index` is the OFFSET (HR_NV_INDEX = 0x01000000
is added internally). So NV index 0x01800000 is passed as 0x00C00000.

Next: wire tpm2_nv_extend into bootm_measure() to extend the real kernel/DTB
measurements at boot; source the factory secret from the DUID/OTP (see
docs/hardening-and-secret-storage.md) instead of the hardcoded demo string.
