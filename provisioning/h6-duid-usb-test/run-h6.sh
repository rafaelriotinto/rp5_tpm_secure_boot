#!/bin/bash
# run-h6.sh -- H6 experiment: does the board disclose the DUID over USB (RPIBOOT)?
#
# Two INDEPENDENT detectors, so a null result is not an artefact of one tool:
#   (1) rpiboot -v  : prints every message filename the DEVICE sends. Metadata
#                     arrives as "*FACTORY_UUID*<hex words>" (usbboot main.c:780-810,
#                     host-side c40-decodes it via decode_duid.c).
#   (2) dumpcap on usbmon : the raw wire, independent of rpiboot's own code paths.
#                     Full payloads (usbmon TEXT mode would truncate at 32 bytes).
#
# MUST run E0 (positive control, UNBURNED board) FIRST. Without it, "we saw
# nothing" is indistinguishable from a broken capture.
#
# Usage:  sudo ./run-h6.sh <label> [rpiboot-args...]
#   sudo ./run-h6.sh E0-16GB-unburned      -d mass-storage-gadget64
#   sudo ./run-h6.sh E1-1GB-burned         -d mass-storage-gadget64
#
# SAFETY: only ever pass -d mass-storage-gadget64 here. That loads a second
# stage over USB; it does NOT flash the EEPROM and does NOT write OTP.
# NEVER point this at secure-boot-recovery5 (that flashes, and burns OTP if
# program_pubkey=1 is set).
set -u

LABEL="${1:?usage: sudo ./run-h6.sh <label> [rpiboot-args...]}"; shift

# Under sudo, $HOME is /root -- resolve the INVOKING user's home instead.
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(getent passwd "${REAL_USER}" | cut -d: -f6)"
USBBOOT_DIR="${USBBOOT_DIR:-${REAL_HOME}/LINUX_YOCTO_RP5_TPM_ENV/usbboot}"
if [ ! -x "${USBBOOT_DIR}/rpiboot" ]; then
  echo "ERROR: rpiboot not found at ${USBBOOT_DIR}/rpiboot" >&2
  echo "       set USBBOOT_DIR=/path/to/usbboot" >&2; exit 1
fi

OUT="$(cd "$(dirname "$0")" && pwd)/results/${LABEL}"
mkdir -p "$OUT"
# dumpcap drops privileges after opening the capture device, so the output
# directory must be writable by the invoking (non-root) user.
chown -R "${REAL_USER}" "$(dirname "${OUT}")" 2>/dev/null
chmod -R u+rwX,go+rX "$(dirname "${OUT}")" 2>/dev/null

# Refuse the dangerous directory outright.
for a in "$@"; do
  case "$a" in
    *secure-boot-recovery*)
      echo "REFUSING: '$a' flashes the EEPROM and can burn OTP. This script is"
      echo "for the read-only USB disclosure test only." >&2; exit 2;;
  esac
done

echo "=== H6 / ${LABEL} ==="
echo "usbboot dir : ${USBBOOT_DIR}"
echo "rpiboot args: $*"
echo "output      : ${OUT}"
echo

modprobe usbmon 2>/dev/null
if [ ! -d /sys/kernel/debug/usb/usbmon ]; then
  echo "ERROR: usbmon not available (need: sudo modprobe usbmon)" >&2; exit 1
fi

echo "[*] waiting for the board in RPIBOOT mode (VID:PID 0a5c:2712)..."
for i in $(seq 1 60); do
  if lsusb | grep -qiE '0a5c:(2712|2711|2764)'; then
    echo "[*] board detected: $(lsusb | grep -iE '0a5c:(2712|2711|2764)')"; break
  fi
  [ "$i" = 60 ] && { echo "ERROR: no board in RPIBOOT mode after 60s." >&2
                     echo "Hold the power button while connecting USB-C." >&2; exit 1; }
  sleep 1
done

# usbmon0 = every USB bus, so we do not have to guess which one it lands on.
# dumpcap drops privileges and would not open a file under the results dir
# ("Permission denied"), so capture into world-writable /tmp and move it after.
CAPTMP="/tmp/h6-${LABEL}-$$.pcapng"
echo "[*] starting capture (dumpcap on usbmon0 -> ${CAPTMP})"
dumpcap -i usbmon0 -w "${CAPTMP}" -q >"${OUT}/dumpcap.log" 2>&1 &
DUMPPID=$!
sleep 2
if ! kill -0 "${DUMPPID}" 2>/dev/null; then
  echo "[!] WARNING: dumpcap died immediately -- see ${OUT}/dumpcap.log"
  sed 's/^/    /' "${OUT}/dumpcap.log"
fi

echo "[*] running rpiboot -v $*"
( cd "${USBBOOT_DIR}" && timeout 120 ./rpiboot -v "$@" ) >"${OUT}/rpiboot.log" 2>&1
RC=$?
echo "[*] rpiboot exit code: ${RC}"

sleep 2
kill -INT "${DUMPPID}" 2>/dev/null; wait "${DUMPPID}" 2>/dev/null
if [ -f "${CAPTMP}" ]; then
  mv "${CAPTMP}" "${OUT}/usb.pcapng"
  chown "${REAL_USER}" "${OUT}/usb.pcapng" 2>/dev/null
  echo "[*] capture: $(stat -c%s "${OUT}/usb.pcapng") bytes"
else
  echo "[!] no capture file produced"
fi

# Did an unsigned second stage actually EXECUTE? (0a5c:0104 = the gadget,
# and a new USB block device = it booted through). This is the real signal
# for E1: on a burned board the ROM should refuse to run unsigned code.
{ echo "[*] rpiboot exit ${RC}"
  echo "[*] post-run USB: $(lsusb | grep -iE '0a5c' || echo 'no Broadcom device')"
  echo "[*] usb block devices: $(lsblk -o NAME,SIZE,MODEL,TRAN 2>/dev/null | grep -i usb || echo none)"
} > "${OUT}/summary.txt"
cat "${OUT}/summary.txt"
echo
echo "=== ANALYSIS ==="
"$(dirname "$0")/analyse-h6.sh" "${OUT}" | tee -a "${OUT}/summary.txt"
