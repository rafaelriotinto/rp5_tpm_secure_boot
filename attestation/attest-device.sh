#!/bin/sh
# attest-device.sh - device side of the attestation protocol (runs on the Pi,
# shell + tpm2-tools; no python needed). Given a server nonce file, produce the
# TPM-signed evidence: a PCR quote and NV_Certify of the attestation and
# measured-boot NV indices, all signed by the AK.
#
# The board-identity step is writing the nonce into the DUID-protected
# attestation NV index -- only a device that can derive the correct
# (DUID-based) secret can do this, so it defeats board/TPM substitution.
#
# Usage: attest-device.sh <nonce.bin> <out-dir>
set -e

NONCE="${1:?nonce file}"
OUT="${2:-/tmp/attest}"
AK=0x81010002            # persistent AK handle
ATTN=0x01800001          # attestation (nonce) NV index, DUID-write-protected
MEAS=0x01800000          # measured-boot NV extend index
AUTH_CTX="rp5-nv-auth-v1"

mkdir -p "$OUT"; cd "$OUT"
NHEX=$(hexdump -e '32/1 "%02x"' "$NONCE")

# DUID-derived secret (same derivation as U-Boot / provisioning)
AUTH=$( { printf '%s' "$AUTH_CTX"; cat /proc/device-tree/chosen/rpi-duid; } |
        sha256sum | cut -d' ' -f1)

# 1) BOARD IDENTITY: write the nonce into the DUID-protected NV index.
#    Requires proving the DUID secret via an HMAC policy session.
tpm2_startauthsession --policy-session -S pol.ctx >/dev/null
tpm2_policyauthvalue -S pol.ctx >/dev/null
tpm2_nvwrite "$ATTN" -P "session:pol.ctx+hex:$AUTH" -i "$NONCE"
tpm2_flushcontext pol.ctx

# 2) SOFTWARE STATE + FRESHNESS: AK-signed quote of the measured PCRs, nonce.
tpm2_quote -c "$AK" -l sha256:0,1,8,9 -q "$NHEX" \
    -m quote.msg -s quote.sig -o pcrs.bin >/dev/null

# 3) AK-signed NV_Certify of the attestation index (== nonce -> board identity)
#    and the measured-boot index (== golden -> boot record). Nonce = freshness.
tpm2_nvcertify -C "$AK" -c o -g sha256 -s rsassa -f plain -q "$NHEX" \
    --size 32 -o attn_cert.sig --attestation attn_cert.msg "$ATTN" >/dev/null
tpm2_nvcertify -C "$AK" -c o -g sha256 -s rsassa -f plain -q "$NHEX" \
    --size 32 -o meas_cert.sig --attestation meas_cert.msg "$MEAS" >/dev/null

echo "attestation evidence written to $OUT"
