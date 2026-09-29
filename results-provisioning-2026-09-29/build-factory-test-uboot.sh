#!/bin/sh
# TEST factory U-Boot for the CONTROL board only (OTP not programmed):
# factory settings (no anti-rollback check, no key locks) WITHOUT the factory
# guard (the control board's firmware key already exists) and with a 3 s boot
# delay so the TPM can be cleared from the U-Boot console. Never signed for,
# nor used on, the demonstration board. Production config restored afterwards.
set -e
ENV=${ENV:-$HOME/LINUX_YOCTO_RP5_TPM_ENV}
CFG=$ENV/rp5_tpm_secure_boot/meta-rpi5-uboot-tpm/recipes-bsp/u-boot/files/uboot-tpm.cfg
OUT=$ENV/releases/factory-test-uboot.bin
cp "$CFG" /tmp/uboot-tpm.cfg.orig
grep -q '^CONFIG_ANTIROLLBACK=y$' "$CFG" || { echo "production config does not enable anti-rollback?"; exit 1; }
restore() { cp /tmp/uboot-tpm.cfg.orig "$CFG"; }
trap restore EXIT
sed -i -e 's/^CONFIG_ANTIROLLBACK=y$/# CONFIG_ANTIROLLBACK is not set/' \
	-e 's/^CONFIG_MEASURE_NV_AUTH_FWKEY=y$/# CONFIG_MEASURE_NV_AUTH_FWKEY is not set/' \
	-e 's/^CONFIG_BOOTDELAY=-2$/CONFIG_BOOTDELAY=3/' "$CFG"
docker exec rp5_tpm_build bash -lc 'cd /LINUX_YOCTO_RP5_TPM_ENV/poky && source oe-init-build-env build >/dev/null 2>&1 && bitbake -c cleansstate u-boot >/dev/null 2>&1 && bitbake u-boot 2>&1 | grep -E "^ERROR|Tasks Summary" | tail -2'
cp "$ENV/poky/build/tmp/deploy/images/raspberrypi5-uboot-tpm/u-boot.bin" "$OUT"
[ "$(strings "$OUT" | grep -c '\[ARB\]')" = 0 ] || { echo "test build still contains the check"; exit 1; }
[ "$(strings "$OUT" | grep -c 'FWKEY\] firmware key locked')" = 0 ] || { echo "test build still locks the firmware key"; exit 1; }
[ "$(strings "$OUT" | grep -c 'FACTORY\] this board')" = 0 ] || { echo "test build still has the guard"; exit 1; }
echo "test factory U-Boot: $OUT ($(strings "$OUT" | grep -o 'U-Boot 2024\.04 ([^)]*)' | head -1))"
restore
cmp -s /tmp/uboot-tpm.cfg.orig "$CFG" && echo "production config restored"
docker exec rp5_tpm_build bash -lc 'cd /LINUX_YOCTO_RP5_TPM_ENV/poky && source oe-init-build-env build >/dev/null 2>&1 && bitbake -c cleansstate u-boot >/dev/null 2>&1 && bitbake u-boot 2>&1 | grep -E "^ERROR|Tasks Summary" | tail -1'
echo "production U-Boot rebuilt in the deploy dir"
