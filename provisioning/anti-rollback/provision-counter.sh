#!/bin/sh
# provision-counter.sh -- one-time provisioning of the anti-rollback TPM NV
# COUNTER index, run ON THE TARGET (tpm2-tools) in the trusted provisioning
# environment. Companion of ../nv-extend/provision-nv-index.sh.
#
# Index 0x01800002, TPM_NT_COUNTER (64-bit, monotonic):
#   nt=counter     -> value can only go up, by TPM2_NV_Increment
#   policywrite    -> incrementing needs a policy session (PolicyAuthValue:
#                     HMAC proof of the authValue, never sent in clear)
#   ppread         -> U-Boot reads it with the (empty) platform auth
#   ownerread|authread -> readable by the owner / with the authValue too
#   no_da          -> not subject to dictionary-attack lockout
#   (NO clear_stclear: the counter must survive reboots)
#
# authValue = SHA256("rp5-nv-counter-v1" || DUID bytes incl. NUL) -- a separate
# label from the measured-boot index, derived the same way, so U-Boot derives
# it at boot from /chosen/rpi-duid. Defining an owner-hierarchy index needs the
# owner auth (set by ../tpm/provision-hierarchy-auth.sh):
#   ownerAuth = SHA256("rp5-owner-auth-v1" || factory_master || DUID)
#
# Inputs (files, never argv -- see red-team H4):
#   DUID_FILE   : the DUID bytes exactly as in /chosen/rpi-duid (incl. NUL)
#                 (defaults to /proc/device-tree/chosen/rpi-duid when present)
#   MASTER_FILE : factory master secret (32 bytes)
# A counter index is unreadable until incremented once, so the script performs
# the first increment (counter = 1). Releases start at version >= 1.
set -e
: "${TPM2TOOLS_TCTI:=device:/dev/tpmrm0}"; export TPM2TOOLS_TCTI
NV_INDEX=0x01800002
AUTH_CTX="rp5-nv-counter-v1"
DUID_FILE="${DUID_FILE:-/proc/device-tree/chosen/rpi-duid}"
MASTER_FILE="${MASTER_FILE:?set MASTER_FILE (factory master, 32 bytes)}"
[ -r "$DUID_FILE" ] || { echo "ERROR: cannot read DUID file $DUID_FILE" >&2; exit 1; }
[ -r "$MASTER_FILE" ] || { echo "ERROR: cannot read $MASTER_FILE" >&2; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT INT TERM
{ printf '%s' "$AUTH_CTX"; cat "$DUID_FILE"; } | sha256sum | cut -d' ' -f1 > "$WORK/auth.hex"
{ printf '%s' "rp5-owner-auth-v1"; cat "$MASTER_FILE"; cat "$DUID_FILE"; } | sha256sum | cut -d' ' -f1 > "$WORK/owner.hex"
chmod 600 "$WORK"/*.hex
echo "[*] counter authValue: $(cut -c1-8 < "$WORK/auth.hex")... (derived, not printed)"

echo "[*] PolicyAuthValue digest via a trial session"
tpm2_startauthsession -S "$WORK/trial.ctx"
tpm2_policyauthvalue -S "$WORK/trial.ctx" -L "$WORK/authval.policy"
tpm2_flushcontext "$WORK/trial.ctx"

if tpm2_nvreadpublic "$NV_INDEX" >/dev/null 2>&1; then
	echo "[!] $NV_INDEX already defined:"; tpm2_nvreadpublic "$NV_INDEX"
	echo "    refusing to redefine (that would reset the counter). Undefine by hand if intended."
	exit 1
fi

echo "[*] defining counter index $NV_INDEX"
tpm2_nvdefine "$NV_INDEX" -C o -P "hex:$(cat "$WORK/owner.hex")" -s 8 \
	-a "nt=counter|policywrite|ppread|ownerread|authread|no_da" \
	-p "hex:$(cat "$WORK/auth.hex")" -L "$WORK/authval.policy"

echo "[*] first increment (makes the index readable; counter = 1)"
tpm2_startauthsession --policy-session -S "$WORK/pol.ctx"
tpm2_policyauthvalue -S "$WORK/pol.ctx"
tpm2_nvincrement "$NV_INDEX" -C "$NV_INDEX" -P "session:$WORK/pol.ctx+hex:$(cat "$WORK/auth.hex")"
tpm2_flushcontext "$WORK/pol.ctx"

echo "[*] public area (record the Name):"; tpm2_nvreadpublic "$NV_INDEX"
echo "[*] value: $(tpm2_nvread "$NV_INDEX" -C p 2>/dev/null | od -An -tx1 | tr -d ' \n')"
echo "[*] done."
