#!/bin/bash
# Host-side test of U-Boot's canonical devicetree digest (boot/bootm.c) --
# the E4 artefact. Compiles the EXACT function from the U-Boot tree against
# U-Boot's own libfdt, then runs it over a blob rebuilt from a board's live
# /proc/device-tree and over variants that must / must not change the digest.
#
# Usage: ./run-test.sh <u-boot-tree> <live-dt-dir>
#   live-dt-dir: an extracted copy of /proc/device-tree from the board
#                (ssh root@board 'cd /proc/device-tree && tar cf - .' | tar xf - -C dir)
set -e
S="${1:?u-boot tree}"; DT="${2:?live device-tree dir}"; cd "$(dirname "$0")"
sed -n "/^static const char \* const dtb_strip_props/,/^static int tcg2_measure_dtb_sanitized/p" "$S/boot/bootm.c" | sed '$d' > extract.c
gcc -O0 -I"$S/scripts/dtc/libfdt" harness.c "$S"/scripts/dtc/libfdt/{fdt,fdt_ro,fdt_strerror}.c -o harness
run(){ ./harness "$1" "$1.stream" >/dev/null && sha256sum "$1.stream" | cut -c1-16; }
python3 fs2dtb.py "$DT" base.dtb >/dev/null
python3 fs2dtb.py "$DT" psu.dtb  --set chosen/power/max_current=00001388 --set chosen/power/usb_max_current_enable=00000001 --set chosen/power/usbpd_power_data_objects=f491010a2cd10200e1c00300b4b00400 --set chosen/power/rpi_power_supply=01 >/dev/null
python3 fs2dtb.py "$DT" warm.dtb --set chosen/bootloader/count=00000002 --set chosen/bootloader/rsts=00001020 --set chosen/kaslr-seed=0011223344556677 >/dev/null
python3 fs2dtb.py "$DT" tamper.dtb --set chosen/bootargs=$(printf 'root=/dev/mmcblk0p2 init=/evil\0' | xxd -p | tr -d '\n') >/dev/null
b=$(run base.dtb); p=$(run psu.dtb); w=$(run warm.dtb); t=$(run tamper.dtb)
printf "base %s\npsu  %s  %s\nwarm %s  %s\ntamper %s  %s\n" "$b" "$p" "$([ $b = $p ] && echo EQUAL-ok || echo DIFFER-FAIL)" "$w" "$([ $b = $w ] && echo EQUAL-ok || echo DIFFER-FAIL)" "$t" "$([ $b != $t ] && echo DIFFER-ok || echo EQUAL-FAIL)"
[ $b = $p ] && [ $b = $w ] && [ $b != $t ] && echo "PASS" || { echo "FAIL"; exit 1; }
