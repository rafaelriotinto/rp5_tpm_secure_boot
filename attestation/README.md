# Remote Attestation (with board binding)

Validated on hardware 2026-08-20 (RPi5 + Infineon SLB9670). Demonstrates that a
monitoring server can remotely verify a device is (1) a genuine enrolled TPM,
(2) running the expected software, (3) with the expected boot record, (4) is the
GENUINE BOARD (not a substituted one), and (5) the report is fresh. See
../docs/threat-model-and-attestation.md for the threat analysis this implements.

## Files

- `attest-device.sh` — device side (Pi, shell + tpm2-tools; NO python needed).
  Deployed to `/usr/bin/attest-device.sh`. Given a nonce file, produces the
  TPM-signed evidence.
- `attest-server.py` — server side (desktop, python3 + openssl). Issues a
  nonce, drives the device over SSH, pulls the evidence, verifies everything.
- `ak.pem` — the enrolled AK public key (enrollment record; public, safe to store).

## Provisioning (one-time, in a trusted environment)

```sh
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -s rsassa -g sha256 -u ak.pub -n ak.name
tpm2_evictcontrol -C o -c ak.ctx 0x81010002        # persist AK
tpm2_readpublic -c 0x81010002 -f pem -o ak.pem     # export AK pub for the server
# attestation nonce NV index, write-protected by the DUID secret:
AUTH=$( { printf 'rp5-nv-auth-v1'; cat /proc/device-tree/chosen/rpi-duid; } | sha256sum | cut -d' ' -f1)
tpm2_startauthsession -S s.ctx; tpm2_policyauthvalue -S s.ctx -L av.policy; tpm2_flushcontext s.ctx
tpm2_nvdefine 0x01800001 -C o -s 32 -a "policywrite|authread|ownerread|no_da" -p "hex:$AUTH" -L av.policy
```
(The measured-boot NV extend index 0x01800000 is provisioned separately, see
../provisioning/nv-extend/.)

## Protocol (per attestation round)

```
server -> device: fresh 32-byte nonce N
device:
  1. write N into the DUID-protected NV index 0x01800001  (HMAC session, DUID secret)
  2. tpm2_quote  PCRs 0,1,8,9 with q=N                    (AK-signed)
  3. tpm2_nvcertify 0x01800001 and 0x01800000, q=N        (AK-signed)
device -> server: quote(.msg/.sig), attn_cert(.msg/.sig), meas_cert(.msg/.sig)
server verifies (attest-server.py):
  - AK signatures on all three  -> genuine ENROLLED TPM
  - nonce echoed in all three   -> freshness (no replay)
  - quote PCR digest == golden  -> good SOFTWARE state
  - attn NV contents == N        -> GENUINE BOARD (only a device that can derive
                                    the DUID secret could write N there)
  - meas NV contents == golden  -> correct BOOT record
  any failure -> REJECT
```

## What each check defends against

- AK signature: forged/non-TPM reports.
- nonce/freshness: replay of a past good attestation.
- PCR + measured-NV == golden: running tampered software (cold board-replacement
  Attack 1: a fake U-Boot cannot extend the DUID-gated NV index, so meas NV !=
  golden -> rejected).
- attn NV == N (board binding): warm-TPM-move Attack 2 -- the fake board cannot
  write N into the DUID-protected index (wrong DUID secret) -> rejected. This is
  the property a plain TPM quote LACKS (a quote proves "a genuine TPM", not "on
  the genuine board").

## Results (hardware)

- Positive: all checks PASS, "device trusted".
- Negative A (measurements != golden): PCR + boot-record checks FAIL -> REJECTED.
- Negative B (fake board, wrong DUID secret): TPM REJECTS the nonce write ->
  board substitution detected, no valid attestation possible.

## Notes / limits

- Golden PCR0 is per-U-Boot-build (it measures U-Boot's version string); the
  enrollment record updates when the image is updated (ties to OTA shipping new
  golden values).
- The whole board-binding rests on the DUID staying confidential -> depends on
  the OS hardening (dm-verity, no root, tpm2_clear lockdown). See
  ../docs/hardening-and-secret-storage.md.
- Demo transport is server-orchestrates-over-SSH; a production device-initiated
  agent would add python3 (via Yocto) or a small C client -- the TPM
  quote/certify + verification (the security-relevant part) is identical.
- Enhancement: TPM salted sessions (encrypt the salt to the EK) hide session
  parameters from bus read-probing (defense in depth).
