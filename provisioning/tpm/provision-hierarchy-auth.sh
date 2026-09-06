#!/bin/sh
# provision-hierarchy-auth.sh -- board-binding sub-step: take ownership of the
# TPM hierarchies and LOCK tpm2_clear.
#
# Closes red-team finding M1. Until this runs, ANY process with /dev/tpmrm0 can
# TPM2_Clear the device: that deletes the owner-created NV indices (0x01800000
# measured boot, 0x01800001 attestation nonce) and regenerates the Storage
# Primary Seed, destroying the enrolled AK. Attestation then fails permanently
# until re-provisioning -- a denial of service, and it also erases the evidence
# an attacker would want gone.
#
# It is ALSO the precondition for the C1 fix (pinning the certified NV index
# Name): pinning the Name only binds attestation to the real index if an
# attacker cannot delete and redefine that index. Deleting requires owner auth,
# so owner auth must not be empty.
#
# ---------------------------------------------------------------------------
# WHICH SECRET, AND WHY NOT THE DUID ALONE
# ---------------------------------------------------------------------------
# The hierarchy auths are DIVERSIFIED from a FACTORY MASTER SECRET and the
# board's DUID:
#
#     auth = SHA256( context || factory_master || DUID )
#
# The DUID alone would NOT do: it is readable on an unhardened board, so anyone
# who can read it could compute the lockout auth and clear the TPM anyway. The
# factory master -- which never leaves the provisioning host -- is what makes
# the value unguessable. The DUID's role here is diversification (a unique auth
# per board), not secrecy. This is the standard key-diversification pattern used
# in smartcard/payment provisioning.
#
# Note the asymmetry with the NV index authValue: that one MUST be derivable
# on-device, because U-Boot needs it unattended at every boot, so it is derived
# from the DUID alone. The hierarchy auths are used ONLY by an administrator
# during provisioning and maintenance, so they can (and should) depend on a
# secret the device never holds.
#
# Trade-off to state in the thesis: a diversified scheme needs no per-board
# secret database (recompute from master + DUID on demand), but compromise of
# the factory master compromises every board. Per-board random secrets invert
# that. Both are defensible; this script implements diversification.
#
# ---------------------------------------------------------------------------
# ORDERING -- run this LAST in TPM provisioning
# ---------------------------------------------------------------------------
#   1. tpm2_createek / tpm2_createak / tpm2_evictcontrol   (owner auth empty)
#   2. provision-nv-index.sh  + attestation NV index       (owner auth empty)
#   3. THIS SCRIPT                                          <- sets auths, locks
# Running it earlier means every later owner-authorized command needs -P.
#
# PREREQUISITE: attest-device.sh must NOT use "-c o" (owner auth) for
# tpm2_nvcertify, or attestation breaks the moment owner auth is set. Use the
# index as its own auth object with an HMAC session instead:
#     tpm2_nvcertify ... -c 0x01800001 -p "session:<hmac.ctx>+file:<auth>"
# (verified working on hardware 2026-09-06).
#
# ---------------------------------------------------------------------------
# RECOVERY -- read before running
# ---------------------------------------------------------------------------
# If the factory master is lost, the lockout auth cannot be recomputed. The
# escape hatch is the PLATFORM hierarchy: TPM2_Clear with platform auth still
# works and can also reset disableClear. platformAuth is volatile (empty at
# every boot), so today anything running on the device can use it.
#
# ==> THEREFORE THIS SCRIPT DOES NOT COMPLETE M1 ON ITS OWN. It closes the
#     LOCKOUT path. The PLATFORM path stays open until U-Boot takes/locks the
#     platform hierarchy at boot (TPM2_HierarchyChangeAuth / disable). Do not
#     claim "tpm2_clear is locked down" until that lands. Until then, treat the
#     platform hierarchy as both the remaining hole AND your recovery path.
#
# Usage:
#   ./provision-hierarchy-auth.sh --master <file> [--check] [--no-disable-clear]
#     --master FILE        factory master secret (raw bytes; NEVER on argv)
#     --check              report state and derived values, change nothing
#     --no-disable-clear   set hierarchy auths but skip TPM2_ClearControl
set -e

MASTER_FILE=""
CHECK_ONLY=0
DO_DISABLE_CLEAR=1

while [ $# -gt 0 ]; do
	case "$1" in
		--master) MASTER_FILE="$2"; shift 2 ;;
		--check) CHECK_ONLY=1; shift ;;
		--no-disable-clear) DO_DISABLE_CLEAR=0; shift ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

: "${TPM2TOOLS_TCTI:=device:/dev/tpmrm0}"
export TPM2TOOLS_TCTI

DUID_NODE=/proc/device-tree/chosen/rpi-duid
[ -r "${DUID_NODE}" ] || { echo "ERROR: cannot read ${DUID_NODE}" >&2; exit 1; }

echo "=== current TPM permanent state ==="
tpm2_getcap properties-variable | sed -n '/TPM2_PT_PERMANENT/,/TPM2_PT_STARTUP/p' || true

if [ "${CHECK_ONLY}" = 1 ] && [ -z "${MASTER_FILE}" ]; then
	echo; echo "(--check with no --master: state only)"; exit 0
fi

[ -n "${MASTER_FILE}" ] || { echo "ERROR: --master <file> is required" >&2; exit 2; }
[ -r "${MASTER_FILE}" ] || { echo "ERROR: cannot read ${MASTER_FILE}" >&2; exit 1; }

# auth = SHA256( context || factory_master || DUID ), one per hierarchy so a
# leak of one does not hand over the others.
derive() {
	{ printf '%s' "$1"; cat "${MASTER_FILE}"; cat "${DUID_NODE}"; } |
		sha256sum | cut -d' ' -f1
}
OWNER_AUTH=$(derive "rp5-owner-auth-v1")
ENDORSE_AUTH=$(derive "rp5-endorsement-auth-v1")
LOCKOUT_AUTH=$(derive "rp5-lockout-auth-v1")

# Write to files: keeping secrets off argv avoids leaking them via
# /proc/PID/cmdline (red-team finding H4).
WORK=$(mktemp -d); trap 'rm -rf "${WORK}"' EXIT INT TERM
for n in owner endorsement lockout; do
	case "$n" in
		owner)       v="${OWNER_AUTH}" ;;
		endorsement) v="${ENDORSE_AUTH}" ;;
		lockout)     v="${LOCKOUT_AUTH}" ;;
	esac
	printf '%s' "$v" > "${WORK}/${n}.hex"
	chmod 600 "${WORK}/${n}.hex"
done

echo
echo "=== derived hierarchy auths (diversified from master + DUID) ==="
echo "  owner       : $(cut -c1-16 < "${WORK}/owner.hex")...   (SHA256, 32 bytes)"
echo "  endorsement : $(cut -c1-16 < "${WORK}/endorsement.hex")..."
echo "  lockout     : $(cut -c1-16 < "${WORK}/lockout.hex")..."
echo "  (full values are NOT printed; recompute them from master + DUID)"

if [ "${CHECK_ONLY}" = 1 ]; then
	echo; echo "--check: nothing changed."; exit 0
fi

echo
echo "!!! This changes TPM ownership state on this board."
echo "!!! Losing the factory master means the lockout auth cannot be recomputed;"
echo "!!! recovery would then require a PLATFORM-auth clear (see header)."
printf 'Type PROVISION to continue: '
read -r confirm
[ "${confirm}" = "PROVISION" ] || { echo "aborted."; exit 1; }

echo
echo "[*] setting owner hierarchy auth"
tpm2_changeauth -c owner "hex:$(cat "${WORK}/owner.hex")"
echo "[*] setting endorsement hierarchy auth"
tpm2_changeauth -c endorsement "hex:$(cat "${WORK}/endorsement.hex")"
echo "[*] setting lockout auth"
tpm2_changeauth -c lockout "hex:$(cat "${WORK}/lockout.hex")"

if [ "${DO_DISABLE_CLEAR}" = 1 ]; then
	echo "[*] TPM2_ClearControl(disableClear=SET) -- blocks the LOCKOUT clear path"
	tpm2_clearcontrol -C l -P "hex:$(cat "${WORK}/lockout.hex")" s
fi

echo
echo "=== resulting state ==="
tpm2_getcap properties-variable | sed -n '/TPM2_PT_PERMANENT/,/TPM2_PT_STARTUP/p' || true
echo
echo "Expect: ownerAuthSet=1 endorsementAuthSet=1 lockoutAuthSet=1 disableClear=1"
echo
echo "REMEMBER: the platform hierarchy is still open (platformAuth is empty at"
echo "every boot), so TPM2_Clear via PLATFORM auth still works. M1 is complete"
echo "only once U-Boot takes/locks the platform hierarchy at boot."
