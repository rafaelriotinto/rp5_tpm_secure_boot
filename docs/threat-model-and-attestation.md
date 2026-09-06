# Threat Model & Attestation Design

Refined threat model (the thesis text is currently too light) plus the
attestation protocol that follows from it. Aug 20 2026.

## 1. What the solution does and does NOT resist

State plainly (do not merely say "out of scope"): the solution does NOT resist
advanced hardware attacks -- SPI/memory bus probing to READ traffic,
decapsulation, fault injection/glitching, chip-off. These can extract OTP
(including the DUID) and observe/limited-tamper the TPM bus. The design assumes
an adversary WITHOUT these capabilities; where such an attacker succeeds, the
board secret (DUID) is disclosed and the guarantees below collapse. This is a
limitation of a discrete external TPM on a platform with no secure enclave, not
a defect of the implementation.

The design DOES resist a SOFTWARE adversary on an intact device and the two
board/TPM-substitution attacks below, PROVIDED the DUID stays confidential
(which requires the OS hardening).

## 2. Attack 1 — cold board replacement (DEFEATED at boot)

Attacker reads the "good" measurement values (e.g. off the bus, or by computing
them from the known-good image), installs a fake boot.img with a fake U-Boot on
a board WITHOUT secure boot, and attaches the TPM. The fake U-Boot tries to
extend the "expected" values so attestation looks good.

Defence: the measured-boot NV extend is authorized by an HMAC policy session
proving the DUID-derived secret (authValue = SHA256(ctx || /chosen/rpi-duid)).
The fake board has a DIFFERENT DUID, so its fake U-Boot cannot produce the
correct authValue -> TPM rejects NV_Extend -> the measured-boot NV index never
receives the good value -> attestation (which certifies that index) detects the
substitution. PCRs alone would NOT catch this (a fake U-Boot can PCR-extend any
value), which is precisely why the DUID-gated NV index is needed.

## 3. Attack 2 — warm TPM move (DEFEATED by attested reboot)

Boot on the REAL board (secure boot on): real U-Boot loads correct PCRs AND the
correct DUID-authorized NV value. Then, WITH POWER ON, physically move the TPM
module to the fake board. The TPM now holds good state; the fake board runs fake
software and can trigger valid AK-signed quotes.

Why boot-time binding fails here: nothing is re-extended on the fake board -- the
good NV state was written by the real board before the move and persists in the
TPM (until a Startup(CLEAR) on reboot). A plain quote from the moved TPM looks
perfect.

The missing property: a TPM quote proves "a genuine TPM with these PCRs", NOT
"this TPM is attached to the genuine BOARD". The AK lives in the (moved) TPM, so
AK-signing proves TPM identity only.

Defence -- SUPERSEDED 2026-09-06. Two designs were considered; the second was
adopted. See attestation/README.md for the implemented protocol and the thesis
scratchpad chapter for the write-up.

### (a) REJECTED: bind at attestation time with a per-round secret

Provision a second "attestation" NV index write-authorized by the DUID secret;
each round the device writes the server nonce into it and NV_Certifies it, so a
valid certify proves a holder of the board secret participated NOW.

This works cryptographically and was implemented and hardware-validated (Aug 20),
but it requires the RUNTIME agent in Linux to hold a board secret every round.
That forced the DUID (or a per-boot derivative) into the OS, kept red-team finding
H4 alive (authValue on argv), and the per-boot-derivative variant additionally
required TPM2_NV_ChangeAuth -- which transmits the NEW authValue as a CLEARTEXT
command parameter on the bit-banged SPI bus, i.e. on the cheapest attack surface
the board has. Avoiding that needs salted sessions with parameter encryption
(ECDH to the EK + KDFa + AES-CFB) and EK certificate verification in U-Boot;
none of it exists, and it is far more new crypto than the measurement path needed.

### (b) ADOPTED: attested reboot (no secret at attestation time)

Keep the board secret entirely inside U-Boot and make FRESHNESS OF THE BOOT the
thing the server checks:

1. The measured-boot index 0x01800000 is `clear_stclear`, so TPM2_Startup(CLEAR)
   empties it at every boot. Only a bootloader that can derive the DUID secret can
   extend it back to the golden value -- proven by HMAC session, never transmitted.
2. The server REQUESTS A REBOOT and then requires, in the next round, BOTH:
   - the TPM's `resetCount` (in TPMS_CLOCK_INFO, inside every signed attest
     structure) to have ADVANCED -- so the restart really happened; and
   - the measured-boot index to be back at the golden value -- which only the
     genuine board can achieve.
3. Reading/certifying the index needs no secret: it carries TPMA_NV_PPREAD, so the
   device authorizes with the EMPTY PLATFORM auth (`tpm2_nvcertify -c p`). That in
   turn lets OWNER auth be set, which blocks the delete/redefine attack below.

An attacker who keeps the TPM powered and ignores the reboot fails the resetCount
check; one who genuinely restarts loses the NV value and cannot restore it.

Validated on hardware 2026-09-06: resetCount 76->77 across a real reboot -> PASS;
the same check without rebooting (77->77) -> REJECTED.

COST, stated honestly: binding is now PERIODIC, not continuous. Between restarts a
warm-moved TPM still produces acceptable evidence, so the guarantee weakens from
"cannot be forged" to "detected within the restart interval". This is a recognised
control rather than a concession -- PCI PTS mandates a periodic firmware self-reset
for the same reason -- and the interval is a policy choice traded against the
disruption of restarting. Section 4 previously dismissed periodic reboot as the
"weaker" option; that judgement predated the analysis of (a)'s bus exposure and is
withdrawn.

### Necessary companion: block delete/redefine of the NV index

Pinning the certified index Name is NOT sufficient on its own. The Name covers
{nvIndex, nameAlg, attributes, authPolicy, dataSize} -- the authValue is NOT part
of it. So an attacker with owner auth can undefine the index and recreate it with
the same public area but their OWN authValue; once written, TPMA_NV_WRITTEN is set
again and the Name is BYTE-IDENTICAL to golden. Demonstrated live 2026-09-06.
The AK is untouched, so all signatures still verify.

Fix: set OWNER auth (M1a), diversified as SHA256(context || factory_master || DUID)
-- the factory master never leaves the provisioning host, and the DUID only
diversifies it per board. Owner auth is PERSISTENT in TPM NV, so it keeps
protecting the index even if the module is lifted off the board. Verified: after
setting it, tpm2_nvundefine is refused, and attestation still passes with no secret
on the device.

## 4. The load-bearing dependency

All of the above rests on the DUID remaining CONFIDENTIAL. If the attacker
extracts the real board's DUID (root on the real board, or a hardware read),
they can compute the secret on the fake board and defeat both bindings. Hence:
- Secure boot protects payload INTEGRITY.
- DUID-derived secret + attestation binding protects against board/TPM
  SUBSTITUTION.
- OS hardening (dm-verity, no root, console + tpm2_clear + /dev/vcio lockdown)
  keeps the DUID confidential.
All three are load-bearing; remove any one and the chain breaks.

Complementary mitigation (weaker): periodic forced reboot (cf. PCI PTS 24h)
bounds the warm-move window and forces re-measurement (which the fake board
fails at the DUID-gated NV extend). The attestation-time binding above is the
stronger, always-on defence and is preferred.

Enhancement (defense in depth, not required for the above): TPM SALTED sessions
-- encrypt the session salt to the EK so the session key never appears on the
bus -- add confidentiality against bus READ-probing. The rolling-nonce HMAC
already prevents the replay/forgery that matters for board-binding, so salted
sessions are an add-on, not the core mechanism.

## 4b. Attestation-time secret exposure and the platform limit (LARGELY SUPERSEDED)

> ⚠️ **UPDATE 2026-09-06.** This section's premise -- "some component on the running
> device must access a board secret on every attestation, this is FUNDAMENTAL" -- was
> true only of the attestation-time-binding design (section 3a), which has been
> REPLACED. Under the adopted attested-reboot design the runtime agent uses NO secret
> at all: the board secret is used only by U-Boot, only at boot, and only as an HMAC
> session key. So mitigations 1-3 below are no longer needed to protect a runtime
> secret; mitigation 2 (strip /chosen/rpi-duid) and the non-root service remain worth
> doing as defence in depth, and become straightforward now that Linux never needs the
> DUID. Mitigation 3 (per-boot delegated credential) is DROPPED -- it was design (a).
>
> What survives unchanged: the no-TEE platform limit at the end of the section, as it
> applies to U-Boot holding the secret at boot. Retained below for the record.

## 4b (original, for the record)

The board-binding (section 3) requires proving the DUID-derived secret AT
ATTESTATION TIME, not just at boot. This is FUNDAMENTAL, not an implementation
choice: proving the genuine board is present *now* (defeating the warm-TPM-move)
means using the genuine SoC's secret *now*. So some component on the running
device must access a board secret on every attestation. This is a genuine
limitation and the thesis states it plainly rather than hiding it.

Facts on the current device (verified Aug 20 2026):
- /proc/device-tree/chosen/rpi-duid is world-readable (mode 0444) -- ANY process
  can read the DUID today. This is worse than root-only and must be fixed.
- /dev/tpmrm0 is group `tss`; TPM use needs the tss group, NOT root. So the
  attestation service does NOT need root.

Mitigations (reduce exposure; none fully eliminates it on this platform):
1. Run the attestation service as a DEDICATED NON-ROOT user in the tss group.
   Limits the blast radius of a service compromise.
2. Strip /chosen/rpi-duid from the device tree U-Boot passes to Linux (as the
   sanitizer already does for the measured copy), so no Linux process sees the
   DUID in the DT.
3. PER-BOOT DELEGATED CREDENTIAL (the real improvement): U-Boot, which is
   secure-boot-protected and derives the DUID inside the SoC, uses the DUID
   ONCE at boot to re-key the attestation NV index to a FRESH RANDOM per-boot
   secret, wipes the DUID, and hands only that ephemeral secret to userspace.
   The attestation service then uses the per-boot secret, never the DUID. Effect:
   the PERMANENT, silicon-burned DUID never enters Linux; a userspace compromise
   leaks only that boot's ephemeral secret (rotated every reboot). It still
   defeats the warm-move (the fake board has neither the per-boot secret -- it
   lived in the real board's RAM -- nor the ability to derive it from its wrong
   DUID). To be designed/implemented alongside the OS hardening.

The fundamental limit (state as such in the thesis): even with all of the above,
SOME normal-world component must touch a board secret, because the Pi 5 has NO
TEE / secure enclave (the BCM2712 Cortex-A76 cores support TrustZone but the SoC
lacks the required secure-world peripherals -- already noted in the background
chapter). On a TEE-equipped platform this board-binding would live in the secure
world, invisible to the normal OS and to root. So the Pi 5 CAN achieve
board-bound attestation but CANNOT fully isolate the board secret the way a
TEE-equipped platform could; it must instead minimize exposure (dedicated
non-root service, ephemeral per-boot credential, DUID stripped from Linux) and
rely on OS hardening. This precise boundary -- what is and is not achievable on a
TEE-less discrete-TPM platform -- is itself a contribution of the thesis.

## 5. Attestation protocol (to implement, userspace/Linux + tpm2-tools)

Provisioning (one-time, trusted env):
- tpm2_createek (ECC, to match the Infineon manufacturer EK certs) /
  tpm2_createak (RSA-2048, rsassa/sha256, parented by the ECC EK); enroll the AK
  public key with the server.
- measured-boot NV extend index 0x01800000 (owner range, DUID-auth).
- attestation NV index 0x01800001 (ordinary, ownerread, DUID-write via
  PolicyAuthValue).
- record golden PCRs (0,1,8,9) and golden measured-boot NV value per
  device+image.
  NOTE: the earlier 0x01C0xxxx indices were in the TCG-reserved handle range
  (0x01c00000-0x01c0ffff, where the manufacturer EK certs live); moved to the
  owner range 0x0180xxxx to avoid colliding with the EK cert slots.

Per round:
  server -> device: nonce N
  device: tpm2_nvwrite <attn-idx> N   (HMAC session, DUID secret)
          tpm2_quote   -l sha256:0,1,8,9 -q N            (AK)  [software state + freshness]
          tpm2_nvcertify <attn-idx> and <measured-idx>   (AK)  [board identity + boot record]
  device -> server: quote, certifies, signatures
  server: verify AK sigs; PCRs==golden; measured-NV==golden; attn-idx==N.
          Any failure (esp. attn-idx write) => reject.

Demo tampering to show detection:
- modify a measurement (cmdline/kernel) -> PCR/NV mismatch -> flagged.
- wrong DUID secret (simulating a fake board) -> nonce write fails -> flagged.
(A real warm-TPM-move needs two boards + physical move; the mechanism is shown
by the DUID-secret write succeeding only with the correct secret.)

## TODO — thesis EK/AK background + implementation consistency

- [ ] Correct the EK/AK background paragraph in the thesis (Overleaf, ~/projs/MsCS/
      thesis/src/). Current draft has two defects: (a) claims the AK is exported
      "along with a certificate binding it to the EK" — NO such certificate exists
      (the EK is a decryption key, cannot sign); (b) omits that the EK↔AK binding
      is proven by CREDENTIAL ACTIVATION (TPM2_MakeCredential/ActivateCredential;
      TPM_ActivateIdentity in 1.2), a challenge-response, not a certificate. Also
      add that the EK by template CANNOT sign (not merely "shouldn't" for privacy).
      Corrected paragraph drafted (in session 51ef3e89 transcript) — apply it.
- [ ] Consistency: the corrected background describes the standard Privacy-CA
      model. The IMPLEMENTATION currently takes the trusted-environment shortcut
      (trusts exported ak.pem directly; no credential activation). Either (preferred)
      implement credential activation (tpm2_makecredential on desktop using the
      saved Infineon EK cert -> tpm2_activatecredential on the Pi; ~15 lines) so the
      demo matches the background, OR state the shortcut explicitly in the impl
      chapter. Do NOT write the impl paragraph until the chosen path is validated
      on hardware (validate-before-writing rule).

## Status

- 2026-08-20: threat model + attestation design documented, and the protocol
  IMPLEMENTED AND VALIDATED ON HARDWARE (RPi5 + Infineon SLB9670). ECC EK + RSA
  AK, owner-range NV indices 0x01800000/0x01800001. Full attestation passes all
  9 server-side checks; negative tests (tampered golden / wrong DUID secret)
  correctly REJECT. See ../attestation/ (attest-device.sh, attest-server.py,
  README.md). Full confidentiality of the DUID still depends on OS hardening
  (separate work item).
