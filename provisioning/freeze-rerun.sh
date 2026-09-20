#!/bin/bash
# freeze-rerun.sh -- re-run the experiments on the frozen release with serial capture.
# Usage: freeze-rerun.sh <step>   (each step is one experiment; output under results/<date>/)
# Board: the demonstration board (BOARD), services only (no root). Serial: /dev/ttyACM0.
set -u
export BOARD=${BOARD:-192.168.10.198} REBOOT_WAIT=${REBOOT_WAIT:-180}
REPO=/home/rafaelrt/projs/MsCS/rp5_tpm_secure_boot
REL=/home/rafaelrt/LINUX_YOCTO_RP5_TPM_ENV/releases
OUT=$REPO/provisioning/freeze-results/$(date +%F); mkdir -p "$OUT"
SER=/dev/ttyACM0
cap_start(){ pkill -x cat 2>/dev/null; stty -F $SER 115200 raw -echo -echoe -echok 2>/dev/null; : > "$OUT/$1.serial"; (cat $SER > "$OUT/$1.serial" &); sleep 1; }
cap_stop(){ pkill -x cat 2>/dev/null; sleep 1; echo "  serial: $(wc -c < "$OUT/$1.serial") bytes"; }
rp5(){ python3 $REPO/agents/server/rp5.py "$@"; }
case "$1" in
  baseline)   # E-base: status + attestation on the frozen release (needs a reboot first)
    cap_start baseline; rp5 reboot >/dev/null; sleep 45; rp5 status | tee "$OUT/baseline.status"; rp5 attest 2>&1 | tee "$OUT/baseline.attest"; cap_stop baseline ;;
  noreboot)   # attested reboot: a round WITHOUT a restart must be refused on restart evidence
    rp5 attest 2>&1 | tee "$OUT/noreboot.attest" ;;
  e2)         # boot.img modified after signing, via the update service (firmware must refuse; fallback)
    cap_start e2; rp5 update $REL/tamper-e2-r12 2>&1 | tee "$OUT/e2.update"; sleep 5; rp5 status | tee "$OUT/e2.status"; cap_stop e2 ;;
  e3)         # devicetree re-signed (control board only: firmware accepts, PCR0 differs) -- run with BOARD=124
    cap_start e3; rp5 update $REL/tamper-e3-r12 2>&1 | tee "$OUT/e3.update"; rp5 status | tee "$OUT/e3.status"; cap_stop e3; rp5 reboot >/dev/null ;;
  e15)        # rollback: install the older signed r11 into the inactive pair, tryboot -> U-Boot must refuse and reset
    cap_start e15; rp5 status | tee "$OUT/e15.before"; rp5 install $REL/ab-r11 2>&1 | tee "$OUT/e15.install"; rp5 tryboot; sleep 75; rp5 status | tee "$OUT/e15.after"; rp5 attest 2>&1 | tee "$OUT/e15.attest"; cap_stop e15 ;;
  e16)        # a normal update cycle r12 -> (r12 reinstalled as r13) is done with a real release; placeholder: status
    rp5 status | tee "$OUT/e16.status" ;;
  *) echo "steps: baseline noreboot e2 e3 e15"; exit 2 ;;
esac
