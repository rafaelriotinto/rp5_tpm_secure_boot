#!/bin/sh
# Build the FACTORY U-Boot: the current release's U-Boot with the anti-rollback
# check compiled out, so an unprovisioned TPM (no counter index) can boot into
# the provisioning service. Output: releases/factory-uboot.bin. The production
# config is restored afterwards; nothing is committed.
#   make-release.py --factory --uboot releases/factory-uboot.bin --version 0 --out releases/factory --bootfs ...
set -e
ENV=${ENV:-$HOME/LINUX_YOCTO_RP5_TPM_ENV}
CFG=$ENV/rp5_tpm_secure_boot/meta-rpi5-uboot-tpm/recipes-bsp/u-boot/files/uboot-tpm.cfg
OUT=$ENV/releases/factory-uboot.bin
grep -q '^CONFIG_ANTIROLLBACK=y$' "$CFG" || { echo "production config does not enable anti-rollback?"; exit 1; }
restore() { sed -i -e "s/^# CONFIG_ANTIROLLBACK is not set$/CONFIG_ANTIROLLBACK=y/" \
	-e "s/^# CONFIG_MEASURE_NV_AUTH_FWKEY is not set$/CONFIG_MEASURE_NV_AUTH_FWKEY=y/" \
	-e "/^CONFIG_RPI_FACTORY_GUARD=y$/d" "$CFG"; }
trap restore EXIT
# factory: no anti-rollback check (no counter yet), no firmware-key lock (provisioning needs the
# key), and the guard that refuses to boot once the key exists
FWKEY=$(grep -c '^CONFIG_MEASURE_NV_AUTH_FWKEY=y$' "$CFG" || true)
sed -i -e 's/^CONFIG_ANTIROLLBACK=y$/# CONFIG_ANTIROLLBACK is not set/' \
	-e 's/^CONFIG_MEASURE_NV_AUTH_FWKEY=y$/# CONFIG_MEASURE_NV_AUTH_FWKEY is not set/' "$CFG"
[ "$FWKEY" = 1 ] && echo "CONFIG_RPI_FACTORY_GUARD=y" >> "$CFG"
docker exec rp5_tpm_build bash -lc 'cd /LINUX_YOCTO_RP5_TPM_ENV/poky && source oe-init-build-env build >/dev/null 2>&1 && bitbake -c cleansstate u-boot >/dev/null 2>&1 && bitbake u-boot 2>&1 | grep -E "^ERROR|Tasks Summary" | tail -2'
cp "$ENV/poky/build/tmp/deploy/images/raspberrypi5-uboot-tpm/u-boot.bin" "$OUT"
[ "$(strings "$OUT" | grep -c '\[ARB\]')" = 0 ] || { echo "factory build still contains the check"; exit 1; }
[ "$(strings "$OUT" | grep -c 'FWKEY\] firmware key locked')" = 0 ] || { echo "factory build still locks the firmware key"; exit 1; }
[ "$FWKEY" != 1 ] || [ "$(strings "$OUT" | grep -c 'FACTORY\] this board')" = 1 ] || { echo "factory build lacks the guard"; exit 1; }
echo "factory U-Boot: $OUT ($(strings "$OUT" | grep -o 'U-Boot 2024\.04 ([^)]*)' | head -1))"
# restore + rebuild the production U-Boot so the deploy dir is production again
restore
docker exec rp5_tpm_build bash -lc 'cd /LINUX_YOCTO_RP5_TPM_ENV/poky && source oe-init-build-env build >/dev/null 2>&1 && bitbake -c cleansstate u-boot >/dev/null 2>&1 && bitbake u-boot 2>&1 | grep -E "^ERROR|Tasks Summary" | tail -1'
echo "production U-Boot restored in the deploy dir"
