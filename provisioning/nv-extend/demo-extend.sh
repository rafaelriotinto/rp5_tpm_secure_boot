#!/bin/sh
# demo-extend.sh - exercises the per-boot NV extend flow that U-Boot must
# replicate (this is the userspace REFERENCE for the U-Boot C implementation).
# Also runs the negative tests proving unauthorized extension is refused.
#
# Per-boot flow (what U-Boot does for each measured component):
#   start policy session -> PolicyAuthValue -> NV_Extend(index, data=digest)
#   with the session HMAC keyed by the factory secret -> FlushContext
#
# Validated on hardware (RPi5, SLB9670) 2026-08-18.
set -e

NV_INDEX=0x01C00000
FACTORY_SECRET="${FACTORY_SECRET:-demo-factory-secret}"
COMPONENT="${1:-kernel-Image-v1}"

echo "[*] Component measurement: sha256(\"${COMPONENT}\")"
printf '%s' "${COMPONENT}" | openssl dgst -sha256 -binary > /tmp/meas.bin
echo "    digest = $(hexdump -e '32/1 "%02x"' /tmp/meas.bin)"

echo "[*] EXTEND via policy session + PolicyAuthValue (HMAC proves the secret)"
tpm2_startauthsession --policy-session -S /tmp/pol.ctx
tpm2_policyauthvalue -S /tmp/pol.ctx
tpm2_nvextend "${NV_INDEX}" -P "session:/tmp/pol.ctx+${FACTORY_SECRET}" -i /tmp/meas.bin
tpm2_flushcontext /tmp/pol.ctx
echo "    extend OK"

echo "[*] NV value now:"
tpm2_nvread "${NV_INDEX}" -C o | hexdump -e '32/1 "%02x"'; echo

echo "[*] NEGATIVE TEST 1: wrong secret (must be rejected)"
tpm2_startauthsession --policy-session -S /tmp/bad.ctx
tpm2_policyauthvalue -S /tmp/bad.ctx
if tpm2_nvextend "${NV_INDEX}" -P "session:/tmp/bad.ctx+WRONG" -i /tmp/meas.bin 2>/dev/null; then
    echo "    !! UNEXPECTED: succeeded with wrong secret"
else
    echo "    OK: rejected (authorization failure)"
fi
tpm2_flushcontext /tmp/bad.ctx 2>/dev/null || true

echo "[*] NEGATIVE TEST 2: cleartext password, no policy session (must be rejected)"
if tpm2_nvextend "${NV_INDEX}" -P "${FACTORY_SECRET}" -i /tmp/meas.bin 2>/dev/null; then
    echo "    !! UNEXPECTED: cleartext write accepted"
else
    echo "    OK: rejected (POLICYWRITE forces HMAC session)"
fi
