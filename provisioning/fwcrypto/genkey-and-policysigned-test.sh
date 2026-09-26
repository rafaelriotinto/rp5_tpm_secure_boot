#!/bin/bash
# Firmware-key feasibility, step 2: generate the OTP ECDSA key and prove that a signature made by the
# FIRMWARE satisfies TPM2_PolicySigned on the board's TPM.
#
# Runs ON the board (Raspberry Pi OS test card, TPM enabled with dtoverlay=tpm-slb9670), as root:
#     sudo ./genkey-and-policysigned-test.sh I-UNDERSTAND-THIS-BURNS-OTP
#
# !!! IRREVERSIBLE: step 1 writes the board's ONLY OTP key slot (key id 1). It cannot be erased or
# !!! regenerated. It does not touch the secure-boot key hash or the DUID rows.
#
# Nothing else is persistent: locks clear at reboot; no NV index is defined (policy session only).
set -u
[ "${1:-}" = "I-UNDERSTAND-THIS-BURNS-OTP" ] || { sed -n 2,12p "$0"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
C=rpi-fw-crypto; K=1; OUT=${OUT:-/root/fwcrypto-results}; mkdir -p "$OUT"; cd "$OUT"
log(){ echo "$*" | tee -a result.txt; }
hex(){ od -An -tx1 "$1" | tr -d ' \n'; }

log "== 0. preconditions ($(date -u +%FT%TZ))"
bl=$(vcgencmd bootloader_version | head -1); log "bootloader: $bl"
[[ "$bl" > "2026/06/17" ]] || { log "ABORT: bootloader predates the per-operation locks (2026-06-17)"; exit 1; }
[ -c /dev/tpmrm0 ] || { log "ABORT: no TPM"; exit 1; }
$C get-key-status $K | tee -a result.txt
if rpi-otp-private-key -c >/dev/null 2>&1; then log "ABORT: key slot already programmed"; exit 1; fi
log "key slot 1 is blank"

log "== 1. generate the key in the firmware (IRREVERSIBLE)"
$C genkey --key-id $K --alg ec 2>&1 | tee -a result.txt || { log "ABORT: genkey failed"; exit 1; }
$C set-key-status $K READ_LOCKED | tee -a result.txt          # raw private key never readable from here on
$C get-key-status $K | tee -a result.txt
$C pubkey --key-id $K --out board-pub.der
openssl ec -pubin -inform DER -in board-pub.der -out board-pub.pem 2>/dev/null
log "public key (safe to publish): $(hex board-pub.der)"
$C privkey --key-id $K --outform hex >/dev/null 2>&1 && log "WARNING: private key readable despite READ_LOCKED" || log "raw private key read refused (expected)"

log "== 2. PolicySigned with a FIRMWARE signature"
tpm2_loadexternal -C n -G ecc -u board-pub.pem -c board.ctx >/dev/null
tpm2_startauthsession -S s.ctx --policy-session
tpm2_policysigned -S s.ctx -c board.ctx -x --raw-data tbs.bin      # nonceTPM || expiration
$C sign --in tbs.bin --key-id $K --alg ec --out sig.der               # CLI hashes tbs.bin, firmware signs the digest
log "signature (DER, $(stat -c %s sig.der) bytes)"
if tpm2_policysigned -S s.ctx -g sha256 -s sig.der -f ecdsa -c board.ctx -x -L pol.dat >/dev/null 2>err.txt
then log "RESULT: TPM ACCEPTED the firmware signature; policy digest $(hex pol.dat)"
else log "RESULT: TPM REFUSED the firmware signature: $(tr '\n' ' ' < err.txt | cut -c1-200)"; fi
tpm2_flushcontext s.ctx

log "== 3. independent check: openssl verifies the firmware signature over tbs.bin"
openssl dgst -sha256 -verify board-pub.pem -signature sig.der tbs.bin 2>&1 | tee -a result.txt

log "== 4. lock signing and HMAC, then try again (must be refused until reboot)"
$C set-key-status $K SIGN_LOCKED | tee -a result.txt
$C set-key-status $K HMAC_LOCKED | tee -a result.txt
$C get-key-status $K | tee -a result.txt
$C sign --in tbs.bin --key-id $K --alg ec --out sig2.der 2>&1 | tail -1 | tee -a result.txt
log "== done; results in $OUT (reboot clears the locks)"
