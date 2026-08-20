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

## 3. Attack 2 — warm TPM move (DEFEATED at attestation)

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

Defence -- bind attestation to the board secret AT ATTESTATION TIME:
1. Provision an "attestation" NV index, write-authorized by the DUID secret
   (PolicyAuthValue, same DUID derivation as the measured-boot index).
2. Each round: server sends fresh nonce N. Device WRITES N into that index,
   which requires an HMAC session proving the DUID secret.
3. Device runs TPM2_NV_Certify on the index (AK-signed): the TPM signs
   "index X contains N".
4. Server requires BOTH a valid AK signature (genuine TPM) AND content == N
   (fresh, and only writable by a holder of the DUID secret = genuine board).

On the fake board, step 2 fails (its software derives the secret from the FAKE
DUID -> wrong authValue -> TPM rejects the write) -> no valid certify -> detected.
The moved AK does not help: AK proves TPM identity; the DUID-gated write proves
BOARD identity; the protocol mandates both. The attacker cannot replay a captured
write (rolling nonceTPM) nor precompute it (N is fresh).

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

## 4b. Attestation-time secret exposure and the platform limit (THESIS-CRITICAL)

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
- tpm2_createek / tpm2_createak; enroll AK public with the server.
- measured-boot NV extend index 0x01C00000 (exists, DUID-auth).
- attestation NV index 0x01C00002 (ordinary, ownerread, DUID-write via
  PolicyAuthValue). [index number TBD]
- record golden PCRs (0,1,8,9) and golden measured-boot NV value per
  device+image.

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

## Status

- 2026-08-20: threat model + attestation design documented. Next: implement
  EK/AK provisioning + the attestation client/server. Full confidentiality of
  the DUID depends on OS hardening (separate work item).
