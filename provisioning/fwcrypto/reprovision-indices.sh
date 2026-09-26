#!/bin/bash
# Re-provision an ALREADY-PROVISIONED board's two TPM NV indices for the firmware-key anchor.
#
#   measured-boot index 0x01800000  (nt=extend, clear_stclear)  policy PolicySigned(fw key, "rp5-nv-meas-v1")
#   anti-rollback counter 0x01800002 (nt=counter)               policy PolicySigned(fw key, "rp5-nv-ctr-v1")
#
# The attestation key and the hierarchy authorisations are kept. The old DUID-rule indices are
# deleted with the owner authorisation, which is read from stdin (64 hex chars) and never stored.
# The firmware key must already exist (genkey-and-policysigned-test.sh) and be unlocked (normal boot
# without lock_device_private_key). The counter is incremented once with a firmware signature, so it
# becomes readable. Runs on the board (Raspberry Pi OS test card) as root:
#     <owner-hex> | sudo ./reprovision-indices.sh REPROVISION
# Output: /root/fwcrypto-results/reprovision.json (public enrollment data: names, policies, key, counter).
set -euo pipefail
[ "${1:-}" = "REPROVISION" ] || { sed -n 2,13p "$0"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
MEAS=0x01800000; CTR=0x01800002; OUT=/root/fwcrypto-results; mkdir -p "$OUT"
read -r OWNER; [[ "$OWNER" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "owner auth: need 64 hex chars on stdin"; exit 2; }
T=$(mktemp -d); trap 'tpm2_flushcontext -t >/dev/null 2>&1 || true; rm -rf "$T"' EXIT; cd "$T"
hex(){ od -An -tx1 "$1" | tr -d ' \n'; }
name(){ tpm2_nvreadpublic "$1" 2>/dev/null | awk '/name:/{print $2; exit}'; }

echo "== 0. preconditions"
st=$(rpi-fw-crypto get-key-status 1); echo "$st"
grep -q "LOCKED" <<<"$st" && { echo "ABORT: firmware key is locked (boot without lock_device_private_key)"; exit 1; }
rpi-fw-crypto pubkey --key-id 1 --out pub.der; openssl ec -pubin -inform DER -in pub.der -out pub.pem 2>/dev/null
old_meas=$(name $MEAS); old_ctr=$(name $CTR)
old_cnt=$(tpm2_nvread $CTR -C $CTR 2>/dev/null | od -An -tx1 | tr -d ' \n' || true)
echo "old names: meas ${old_meas:-none} counter ${old_ctr:-none} (counter value ${old_cnt:-?})"

echo "== 1. policies: PolicySigned(firmware key, policyRef)"
tpm2_loadexternal -C n -G ecc -a "sign|userwithauth" -u pub.pem -c key.ctx -n key.name >/dev/null
printf 'rp5-nv-meas-v1' > ref.meas; printf 'rp5-nv-ctr-v1' > ref.ctr
for r in meas ctr; do
  tpm2_startauthsession -S trial.ctx
  tpm2_policysigned -S trial.ctx -c key.ctx -q ref.$r -L pol.$r >/dev/null
  tpm2_flushcontext trial.ctx
  echo "  $r policy $(hex pol.$r)"
done
echo "  key name $(hex key.name)"

echo "== 2. delete the DUID-rule indices (owner authorisation)"
for i in $MEAS $CTR; do
  if [ -n "$(name $i)" ]; then tpm2_nvundefine $i -C o -P "hex:$OWNER" && echo "  $i deleted"; fi
done

echo "== 3. define the firmware-key indices (owner authorisation, empty index authValue)"
tpm2_nvdefine $MEAS -C o -P "hex:$OWNER" -s 32 -L pol.meas \
  -a "nt=extend|policywrite|ppread|authread|ownerread|no_da|clear_stclear" >/dev/null
tpm2_nvdefine $CTR -C o -P "hex:$OWNER" -s 8 -L pol.ctr \
  -a "nt=counter|policywrite|ppread|ownerread|authread|no_da" >/dev/null
echo "  new names: meas $(name $MEAS) counter $(name $CTR)"

echo "== 4. first counter increment, authorised by a firmware signature"
tpm2_nvincrement $CTR -C $CTR --cphash cp.bin >/dev/null
tpm2_startauthsession --policy-session -S s.ctx
tpm2_policysigned -S s.ctx -c key.ctx -x --cphash-input cp.bin -q ref.ctr --raw-data tbs.bin
rpi-fw-crypto sign --in tbs.bin --key-id 1 --alg ec --out sig.der
tpm2_policysigned -S s.ctx -g sha256 -s sig.der -f ecdsa -c key.ctx -x --cphash-input cp.bin -q ref.ctr >/dev/null
tpm2_nvincrement $CTR -C $CTR -P session:s.ctx
tpm2_flushcontext s.ctx
cnt=$(tpm2_nvread $CTR -C $CTR | od -An -tx1 | tr -d ' \n'); echo "  counter now 0x$cnt ($((16#$cnt)))"

echo "== 5. negative control: increment without a signature must fail"
tpm2_nvincrement $CTR -C $CTR >/dev/null 2>&1 && echo "  UNEXPECTED: accepted" || echo "  refused (expected)"

python3 - "$OUT/reprovision.json" <<EOF
import json,sys
json.dump({"meas_index":"$MEAS","meas_name":"$(name $MEAS)","meas_policy":"$(hex pol.meas)",
 "counter_index":"$CTR","counter_name":"$(name $CTR)","counter_policy":"$(hex pol.ctr)",
 "counter":$((16#$cnt)),"fw_key_name":"$(hex key.name)","fw_pubkey_der":"$(hex pub.der)",
 "old":{"meas_name":"${old_meas}","counter_name":"${old_ctr}","counter":"${old_cnt}"}},
 open(sys.argv[1],"w"),indent=2)
EOF
echo "== done: $OUT/reprovision.json"
