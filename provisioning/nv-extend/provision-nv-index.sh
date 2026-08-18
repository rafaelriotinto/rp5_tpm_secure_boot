#!/bin/sh
# provision-nv-index.sh - one-time TPM provisioning of the measured-boot NV
# extend index (Stage 5). Run on the target (Linux, tpm2-tools) during
# provisioning in a controlled environment.
#
# Creates NV index 0x01C00000 as an EXTEND-type index whose write is gated by
# a policy session that must satisfy PolicyAuthValue -- i.e. the caller must
# prove knowledge of the index authValue ("factory secret") via an HMAC
# session; the secret never travels the bus in cleartext, and cleartext
# (password) authorization is refused.
#
# Attributes:
#   nt=extend      -> value can only be updated via NV_Extend (PCR-like)
#   policywrite    -> writing requires a policy session (forces HMAC auth)
#   authread|ownerread -> readable with the authValue or by the owner
#   no_da          -> not subject to dictionary-attack lockout
#   clear_stclear  -> value resets to 0 on every power cycle (PCR-like)
#
# Validated on hardware (RPi5, SLB9670) 2026-08-18.
set -e

NV_INDEX=0x01C00000
NV_SIZE=32
# NV auth domain-separation context; MUST match U-Boot MEASURE_NV_AUTH_CTX.
AUTH_CTX="rp5-nv-auth-v1"

# The NV index authValue ("factory secret") is derived from the SoC DUID that
# the firmware exposes at /chosen/rpi-duid. The DUID lives in OTP (not on the
# SD card); U-Boot derives the same value inside the SoC at boot, so the secret
# never travels on removable media. See docs/hardening-and-secret-storage.md.
#   authValue = SHA256( AUTH_CTX || <bytes of /chosen/rpi-duid incl. NUL> )
FACTORY_SECRET=$(
	{ printf '%s' "${AUTH_CTX}"; cat /proc/device-tree/chosen/rpi-duid; } |
	sha256sum | cut -d' ' -f1
)
echo "[*] DUID-derived authValue = ${FACTORY_SECRET}"

echo "[*] Building PolicyAuthValue digest via a trial session"
tpm2_startauthsession -S /tmp/trial.ctx
tpm2_policyauthvalue -S /tmp/trial.ctx -L /tmp/authval.policy
tpm2_flushcontext /tmp/trial.ctx

echo "[*] Defining NV extend index ${NV_INDEX}"
tpm2_nvundefine "${NV_INDEX}" 2>/dev/null || true
tpm2_nvdefine "${NV_INDEX}" -C o -s "${NV_SIZE}" \
    -a "nt=extend|policywrite|authread|ownerread|no_da|clear_stclear" \
    -p "hex:${FACTORY_SECRET}" \
    -L /tmp/authval.policy

echo "[*] NV public area:"
tpm2_nvreadpublic "${NV_INDEX}"
echo "[*] Done. Record the NV 'name' above -- U-Boot needs it for the"
echo "    NV_Extend cpHash computation."
