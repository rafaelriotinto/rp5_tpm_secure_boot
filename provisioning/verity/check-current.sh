#!/bin/bash
# One-liner wrapper: verify the CURRENT build's verity image and print the cmdline.
exec "$(dirname "$0")/verity-cmdline.sh" \
  /home/rafaelrt/LINUX_YOCTO_RP5_TPM_ENV/poky/build/tmp/deploy/images/raspberrypi5-uboot-tpm/core-image-base-raspberrypi5-uboot-tpm.rootfs.ext4.verity \
  /home/rafaelrt/LINUX_YOCTO_RP5_TPM_ENV/poky/build/tmp/work-shared/raspberrypi5-uboot-tpm/dm-verity/core-image-base.ext4.verity.env \
  /dev/mmcblk0p3
