# TPM provisioning / board binding

Rafael's framing (2026-09-06): what we loosely call "provisioning" is really **two
sub-steps**, and it is worth naming them separately in the thesis because they anchor
different things.

| | Sub-step | Anchors | Irreversible? |
|---|---|---|---|
| **A** | **Secure-boot key burn** — SHA256(N‖e) of the owner RSA key into OTP, via `usbboot` | *what may run* | **YES** — permanent |
| **B** | **TPM setup / board binding** — EK, AK, NV indices, authValues, `tpm2_clear` lock | *which board and which TPM* | no (re-provisionable) |

Sub-step **A** makes the boot chain authentic; **B** ties attestation to *this* board and
*this* TPM. Neither alone is sufficient: A without B means a genuine-but-substituted TPM
still signs clean quotes; B without A means an attacker can boot their own code and forge
the measurements before they ever reach the TPM.

**Ordering note.** `docs/provisioning-design.md` runs **B before A** (stage 5 TPM
provisioning, stage 6 OTP burn) deliberately: the irreversible step goes last, after
everything else has been validated on the board.

## Scripts

| Script | Sub-step | Status |
|---|---|---|
| `../nv-extend/provision-nv-index.sh` | B — measured-boot NV extend index `0x01800000` | validated on hw 2026-08-18 |
| `provision-hierarchy-auth.sh` | B — hierarchy auths + `tpm2_clear` lock (**M1**) | **written 2026-09-06, NOT yet run on hardware** |
| *(attestation NV index `0x01800001`)* | B | inline in `attestation/README.md`; should become a script |
| *(EK/AK creation + persist)* | B | inline in `attestation/README.md`; should become a script |

Run order within sub-step B — **hierarchy auth LAST**:

```
1. tpm2_createek / tpm2_createak / tpm2_evictcontrol 0x81010002   (owner auth empty)
2. provision-nv-index.sh                       -> 0x01800000      (owner auth empty)
3. attestation NV index                        -> 0x01800001      (owner auth empty)
4. provision-hierarchy-auth.sh --master <file>                    <- sets auths, locks clear
```

Doing step 4 earlier just means every later owner-authorized command needs `-P`.

## The two secrets, and why they differ

```
NV index authValue  = SHA256( "rp5-nv-auth-v1" || DUID )
hierarchy auths     = SHA256( <context> || factory_master || DUID )
```

The difference is **who needs the secret and when**:

- The **NV authValue** must be derivable **on the device, unattended, at every boot**,
  because U-Boot uses it to extend the measured-boot index. It therefore has to come from
  something the SoC holds — the DUID. Its confidentiality rests on the boot chain and OS
  hardening (secure boot, no U-Boot console, DT node stripped, `/dev/vcio` locked).
- The **hierarchy auths** are used **only by an administrator**, during provisioning and
  maintenance. Nothing on the device ever needs them. So they mix in a **factory master
  secret that never leaves the provisioning host**, with the DUID as the diversifier giving
  a unique value per board.

The DUID alone would be wrong for the hierarchy auths: anyone able to read it could compute
them and clear the TPM regardless. This is standard **key diversification** (master + device
ID → per-device key), the same pattern used in smartcard and payment provisioning — which
also connects neatly to the PCI PTS / CC-JIL framing in the threat-model chapter.

**Trade-off to state honestly:** diversification needs no per-board secret database
(recompute from master + DUID), but a leak of the factory master compromises every board.
Per-board random secrets invert that: no single point of failure, but you must store them.

## ⚠️ What `provision-hierarchy-auth.sh` does and does not close

It closes the **LOCKOUT** path to `TPM2_Clear` (sets lockout auth, then
`TPM2_ClearControl(disableClear)`).

It does **not** close the **PLATFORM** path. `platformAuth` is volatile — empty at every
boot — so anything running on the device can still clear the TPM via the platform hierarchy,
and platform auth can also reset `disableClear`. **M1 is complete only when U-Boot takes or
disables the platform hierarchy at boot.** Do not claim "`tpm2_clear` is locked down" before
that.

Until then the platform hierarchy is simultaneously the remaining hole **and** the recovery
path if the factory master is ever lost.

## Why this matters beyond denial of service

`TPM2_Clear` deletes the owner-created NV indices and regenerates the Storage Primary Seed,
destroying the enrolled AK. The EK survives (it is derived from the Endorsement Primary
Seed, which a clear does not touch), but the AK is created with randomness and cannot be
reproduced — so attestation fails permanently until re-provisioning.

That is fail-*safe* rather than fail-*open*: an attacker gains no forgery capability. But it
is still a denial of service, it erases the measured-boot history an attacker would want
gone, and — most importantly — **it is the precondition for the C1 fix**. Pinning the
certified NV index Name only binds attestation to the real index if an attacker cannot
delete and redefine that index, which requires owner auth to be non-empty.
