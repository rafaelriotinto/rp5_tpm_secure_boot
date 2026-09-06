# Remote Attestation (with board binding by attested reboot)

Validated on hardware (RPi5 + Infineon SLB9670). A monitoring server remotely
verifies that a device is (1) a genuine enrolled TPM, (2) running the expected
software, (3) with the expected boot record, (4) the GENUINE BOARD rather than a
substituted one, and (5) reporting freshly. See
../docs/threat-model-and-attestation.md for the threat analysis.

> **Redesigned 2026-09-06 — "Option B", attested reboot.** The previous design
> proved board identity *at attestation time*, by having Linux write the server
> nonce into a DUID-protected NV index. That required the runtime agent to hold
> the board secret. It has been replaced: **this script now uses no secret at
> all.** Board binding lives entirely in U-Boot. See "Why" below.

## Files

- `attest-device.sh` — device side (Pi, shell + tpm2-tools; no python needed).
  Deployed to `/usr/bin/attest-device.sh`. Given a nonce file, produces the
  TPM-signed evidence. **Holds no secret.**
- `attest-server.py` — server side (desktop, python3 + openssl). Issues a nonce,
  drives the device over SSH, pulls the evidence, verifies everything.
- `ak.pem` — the enrolled AK public key (enrollment record; public).
- `attest-state.json` — last observed TPM `resetCount`, so a requested reboot can
  be shown to have actually happened.

## Provisioning (one-time, in a trusted environment)

```sh
tpm2_createek -c ek.ctx -G ecc -u ek.pub        # ECC, to match the Infineon EK certs
tpm2_createak -C ek.ctx -c ak.ctx -G rsa -s rsassa -g sha256 -u ak.pub -n ak.name
tpm2_evictcontrol -C o -c ak.ctx 0x81010002        # persist AK
tpm2_readpublic -c 0x81010002 -f pem -o ak.pem     # export AK pub for the server
```
The measured-boot NV extend index `0x01800000` is provisioned separately — see
`../provisioning/nv-extend/`. It must carry **`ppread`** so the device can certify
it with empty platform auth (below). Hierarchy auths and the `tpm2_clear` lockdown
are a separate step — see `../provisioning/tpm/`.

Capture at enrollment, into `attest-server.py`: the golden PCRs, the golden NV
value, and the NV index **Name** (`tpm2_nvreadpublic 0x01800000`).

There is no longer an attestation-nonce index; `0x01800001` was removed.

## Protocol (per attestation round)

```
server -> device: fresh 32-byte nonce N
device (NO SECRET USED):
  1. tpm2_quote      PCRs 0,1,8,9 with q=N            (AK-signed)
  2. tpm2_nvcertify  0x01800000  with q=N, -c p       (AK-signed, empty platform auth)
device -> server: quote(.msg/.sig), meas_cert(.msg/.sig)

server verifies (attest-server.py):
  - AK signatures on both              -> genuine ENROLLED TPM
  - TPM_GENERATED magic + attest type  -> produced inside the TPM; no quote/NV confusion
  - PCR selection == sha256:{0,1,8,9}  -> the registers we think we checked
  - nonce echoed in both               -> freshness (no replay)
  - quote PCR digest == golden         -> good SOFTWARE state
  - certified NV index Name == golden  -> the RIGHT index was certified
  - meas NV contents == golden         -> correct BOOT record + BOARD BINDING
  - [when REQUIRE_REBOOT=1] resetCount advanced -> the restart really happened
  any failure -> REJECT
```

Usage:

```sh
python3 attest-server.py                 # ordinary round
REQUIRE_REBOOT=1 python3 attest-server.py    # after asking the device to reboot
```

## Why board binding works without a secret

The measured-boot index is declared `nt=extend | policywrite | ppread | ...
| clear_stclear`. Three different authorities gate three different operations, and
only the one U-Boot performs needs the board secret:

| Operation | Gated by | Secret on the device? |
|---|---|---|
| **write** (extend) | `PolicyAuthValue` over `SHA256("rp5-nv-auth-v1" \|\| DUID)` — U-Boot only, proven by HMAC session | — |
| **read / certify** | empty **platform** auth, via `TPMA_NV_PPREAD` | **none** |
| **delete / redefine** | **owner** auth, `SHA256(ctx \|\| factory_master \|\| DUID)`, held off-device | **none** |

`clear_stclear` means `TPM2_Startup(CLEAR)` empties the index at every boot. Only a
bootloader able to derive the DUID secret can extend it back to the golden value, so
after a genuine restart a substituted board cannot produce it.

The server drives this by **requesting a reboot** and then requiring both that
`resetCount` advanced and that the index is back at golden. An attacker who keeps the
TPM powered and skips the restart fails the first; one who really restarts fails the
second.

Nothing secret crosses the SPI bus: the extend *data* is the (public) measurement, and
the authValue is only ever an HMAC session key — proof of knowledge, never transmitted.

## What each check defends against

- **AK signature** — forged or non-TPM reports.
- **Magic / attest type / PCR selection** — a `NV_Certify` blob submitted as a quote.
  Without the type check, an attacker could write the (public) golden PCR composite
  into their own index, certify it, and pass the software-state check with PCRs that
  never held those values.
- **Certified index Name** — evidence produced from an attacker-defined index. The Name
  covers handle, attributes and policy. *Necessary but not sufficient on its own:* the
  authValue is **not** part of the Name, so an index deleted and recreated with the same
  public area has an identical Name — which is why owner auth must be set.
- **Nonce / freshness** — replay of a past good attestation.
- **PCR + measured-NV == golden** — tampered software; and a fake U-Boot cannot extend
  the DUID-gated index, so the boot record fails (cold board replacement).
- **resetCount advanced** — a warm-moved TPM whose holder ignores the reboot request.

## Results (hardware, 2026-09-06)

- Positive: all checks PASS with **no secret on the device**.
- resetCount advanced 76 -> 77 across a genuine reboot -> PASS.
- Same check without rebooting (77 -> 77) -> **REJECTED**.
- Rogue-index forgery (attacker-defined index, no board secret) -> **REJECTED**
  on the Name check.
- `NV_Certify` blob submitted as a quote -> **REJECTED** on the type check.
- Delete/redefine of the real index, once owner auth is set -> **REFUSED** by the TPM.

## Notes / limits

- **Binding is periodic, not continuous.** Between restarts a warm-moved TPM still
  yields acceptable evidence, so the guarantee is "detected within the restart
  interval" rather than "cannot be forged". Cf. PCI PTS, which mandates a periodic
  firmware self-reset for the same reason. The interval is a policy choice.
- **The index currently commits to the kernel only.** DTB, cmdline and initrd are in
  ordinary PCRs, which a fake board can reproduce. Planned fix: extend the index with
  `SHA256(PCR0 || PCR1 || PCR8 || PCR9)` — the quote's own `pcrDigest` — so the index
  commits to the whole measured state (TODO.md D0b).
- **Golden PCR0 is unstable across power sources** until the DTB sanitizer also strips
  `/chosen/power` (USB-PD negotiation results) — TODO.md D0.
- Golden PCR0 is also per-U-Boot-build; the enrollment record updates with the image
  (ties to OTA shipping new golden values).
- The platform hierarchy must stay enabled, since `-c p` relies on it. This rules out
  having U-Boot disable it — judged near-worthless anyway, as a TPM lifted off the board
  is powered up outside U-Boot's control.
- Demo transport is server-orchestrates-over-SSH; a production device-initiated agent
  would add python3 or a small C client. The TPM operations and verification — the
  security-relevant part — are identical.
