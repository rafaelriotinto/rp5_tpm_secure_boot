#!/bin/sh
# attest-device.sh - device side of the attestation protocol (runs on the Pi,
# shell + tpm2-tools; no python needed). Given a server nonce file, produce the
# TPM-signed evidence: a PCR quote and an NV_Certify of the measured-boot index,
# both signed by the AK.
#
# ---------------------------------------------------------------------------
# THIS SCRIPT USES NO SECRET (Option B, "attested reboot", adopted 2026-09-06)
# ---------------------------------------------------------------------------
# It previously derived the DUID-based secret and wrote the server nonce into a
# secret-protected NV index, to prove at ATTESTATION time that the genuine board
# was present (defeating a warm TPM move). That is gone. Board binding now lives
# entirely in U-Boot:
#
#   - the measured-boot index 0x01800000 is declared `clear_stclear`, so its
#     contents are invalidated by TPM2_Startup(TPM_SU_CLEAR) at every boot;
#   - only a bootloader that can derive the DUID-based secret can extend it back
#     to the golden value, and it proves that secret through an HMAC/policy
#     session -- knowledge, never transmission;
#   - so after a genuine restart, a substituted board cannot restore the value.
#
# The server drives this by REQUESTING A REBOOT and then requiring (a) the TPM's
# resetCount to have advanced, and (b) the measured-boot index to be back at the
# golden value. An attacker who keeps the TPM powered and skips the restart
# fails (a); one who really restarts fails (b).
#
# Consequences, and why this is better on this hardware:
#   - no secret is used at attestation time, so none can be recovered from the
#     bit-banged SPI bus on the exposed 40-pin header (the cheapest surface on
#     the board), and none has to be held by Linux;
#   - Linux never needs the DUID at all, so stripping /chosen/rpi-duid and
#     locking /dev/vcio becomes achievable rather than aspirational;
#   - red-team finding H4 (authValue leaked via /proc/PID/cmdline) disappears
#     rather than being mitigated: there is no authValue here any more.
#
# Cost, stated honestly: binding is now PERIODIC, not continuous. Between
# restarts a warm-moved TPM still yields acceptable evidence, so the guarantee
# is "detected within the restart interval" rather than "cannot be forged".
# Cf. PCI PTS, which mandates a periodic firmware self-reset for this reason.
#
# Usage: attest-device.sh <nonce.bin> <out-dir>
set -e

NONCE="${1:?nonce file}"
OUT="${2:-/tmp/attest}"
AK=0x81010002            # persistent AK handle
MEAS=0x01800000          # measured-boot NV extend index (DUID-gated, U-Boot only)

mkdir -p "$OUT"; cd "$OUT"
NHEX=$(hexdump -e '32/1 "%02x"' "$NONCE")

# 1) SOFTWARE STATE + FRESHNESS: AK-signed quote of the measured PCRs, nonce as
#    qualifying data. The signed structure also carries the TPM's clock and
#    reset counters, which the server uses to confirm a restart really happened.
tpm2_quote -c "$AK" -l sha256:0,1,8,9 -q "$NHEX" \
    -m quote.msg -s quote.sig -o pcrs.bin >/dev/null

# 2) BOOT RECORD + BOARD BINDING: AK-signed NV_Certify of the measured-boot
#    index. Reading is open (ownerread|authread), so no secret is needed here;
#    the binding comes from who was able to WRITE it, which is U-Boot alone.
# -c p: authorize the READ with the PLATFORM hierarchy, whose auth is empty at
# every boot -- so no secret is needed here. The index carries TPMA_NV_PPREAD for
# this. Reads need no protection (the measurement is public); only WRITES do, and
# those stay gated by PolicyAuthValue over the DUID-derived secret, which only
# U-Boot holds and which is proven by HMAC session, never transmitted.
# Using platform rather than owner auth is what lets OWNER auth be set (blocking
# the undefine/redefine attack) while attestation stays completely secret-free.
tpm2_nvcertify -C "$AK" -c p -g sha256 -s rsassa -f plain -q "$NHEX" \
    --size 32 -o meas_cert.sig --attestation meas_cert.msg "$MEAS" >/dev/null

echo "attestation evidence written to $OUT"
