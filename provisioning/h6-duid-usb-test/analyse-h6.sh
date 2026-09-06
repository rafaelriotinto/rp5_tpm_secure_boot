#!/bin/bash
# analyse-h6.sh -- scan an H6 capture for DUID disclosure.
# Usage: ./analyse-h6.sh <results-dir>
set -u
D="${1:?usage: ./analyse-h6.sh <results-dir>}"

# Known DUID of the 1 GB burned board, in every form it could appear:
#   - printable (rpiboot's c40-DECODED form, as written to the metadata JSON)
#   - the ASCII key name that carries it on the wire
DUID_DEC="911045808726"
DUID_PAD="000000911045808726"

hit() { printf '  %-46s %s\n' "$1" "$2"; }

echo "--- detector 1: rpiboot -v message log ---"
if [ -f "${D}/rpiboot.log" ]; then
  n=$(grep -ac "FACTORY_UUID" "${D}/rpiboot.log" 2>/dev/null || true); n=${n:-0}
  hit "FACTORY_UUID in rpiboot log:" "${n} hit(s)"
  [ "$n" -gt 0 ] && grep -n "FACTORY_UUID" "${D}/rpiboot.log" | head -5 | sed 's/^/      /'
  m=$(grep -aciE "${DUID_DEC}" "${D}/rpiboot.log" 2>/dev/null || true); m=${m:-0}
  hit "DUID digits (${DUID_DEC}) in log:" "${m} hit(s)"
  echo "    -- messages the DEVICE sent (first 25) --"
  grep -a "Received message" "${D}/rpiboot.log" | head -25 | sed 's/^/      /'
  [ -s "${D}/rpiboot.log" ] || echo "      (log empty)"
else
  echo "  (no rpiboot.log)"
fi

echo
echo "--- detector 2: raw USB capture ---"
if [ -f "${D}/usb.pcapng" ]; then
  sz=$(stat -c%s "${D}/usb.pcapng")
  hit "capture size:" "${sz} bytes"
  if [ "$sz" -lt 200 ]; then
    echo "  WARNING: capture is essentially empty -- a null result here proves NOTHING."
    echo "           Check permissions / that usbmon0 saw the right bus."
  fi
  for pat in "FACTORY_UUID" "${DUID_PAD}" "${DUID_DEC}"; do
    n=$(strings -a "${D}/usb.pcapng" | grep -ac "${pat}" 2>/dev/null || true); n=${n:-0}
    hit "'${pat}' on the wire:" "${n} hit(s)"
    [ "$n" -gt 0 ] && strings -a "${D}/usb.pcapng" | grep "${pat}" | head -3 | sed 's/^/      /'
  done
  echo "    -- all '*'-prefixed metadata messages seen on the wire --"
  strings -a "${D}/usb.pcapng" | grep -aE '^\*[A-Z_]+' | sort -u | head -20 | sed 's/^/      /'
else
  echo "  (no usb.pcapng)"
fi

echo
echo "--- metadata JSON written by rpiboot (if any) ---"
find "${D}" "$(dirname "${D}")" -maxdepth 3 -name '*.json' 2>/dev/null | head -5 | sed 's/^/      /'

echo
echo "--- VERDICT ---"
L=$(grep -ac "FACTORY_UUID" "${D}/rpiboot.log" 2>/dev/null || true); L=${L:-0}
W=$(strings -a "${D}/usb.pcapng" 2>/dev/null | grep -ac "FACTORY_UUID" || true); W=${W:-0}
if [ "$L" -gt 0 ] || [ "$W" -gt 0 ]; then
  echo "  DUID WAS DISCLOSED over USB (log=${L} wire=${W})."
  echo "  Expected for an UNBURNED board (this is the positive control)."
  echo "  On a BURNED board this would be a CRITICAL finding."
else
  echo "  No DUID disclosure detected (log=0 wire=0)."
  echo "  Meaningful ONLY if the positive control (E0, unburned board) showed hits"
  echo "  with this same tooling. Otherwise the capture may simply be blind."
fi
