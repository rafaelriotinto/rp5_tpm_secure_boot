#BUILD

docker build \
  --build-arg UNAME=$(whoami) \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t ubuntu-$(whoami) \
  .


docker run -it \
  -v /home/rafaelrt/LINUX_DOCKER_SHARE:/LINUX_DOCKER_SHARE \
  -w /LINUX_DOCKER_SHARE \
  --name linux_build \
   ubuntu-rafaelrt /bin/bash


#to exit
exit 

#to start again
docker start -ai linux_build

#once inside the docker machine, run:
cd poky
source oe-init-build-env 

#to flash
#IMPORTANT: Unmount partitions first
#Before flashing, unmount the auto-mounted partitions:

sudo umount /dev/mmcblk0p1
sudo umount /dev/mmcblk0p2

bunzip2 -c build/tmp/deploy/images/raspberrypi5-uboot-tpm/core-image-base-raspberrypi5-uboot-tpm.rootfs.wic.bz2 | sudo dd of=/dev/mmcblk0 bs=4M status=progress conv=fsync

sync

#to print the FDT inside u-boot
fdt addr ${fdtcontroladdr}    # select the FDT
fdt print    

#to delete the container
docker rm -f linux_build

// TPM in U-boot
tpm2 init
tpm2 startup TPM2_SU_CLEAR
tpm2 info
tpm2 pcr_read 0 0x10000000

// bitbake u-boot
bitbake -c cleansstate u-boot
bitbake core-image-base