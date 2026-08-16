# Yocto Build Container

Reproducible Ubuntu 22.04 build environment for the Raspberry Pi 5 secure/measured
boot project. All compilation (Yocto, U-Boot, kernel) happens inside this container;
only flashing the SD card and the serial console are done on the host.

## Prerequisites

- Docker installed, and your user able to run it (`sudo usermod -aG docker $USER`,
  then log out/in)
- ~150 GB of free disk space for the Yocto build tree

## 1. Create the shared work directory

The container is stateless: all sources and build artifacts live in a host
directory bind-mounted into the container. Create it first:

```bash
mkdir -p $HOME/LINUX_YOCTO_RP5_TPM_ENV
```

Everything (Yocto tree, U-Boot sources, build output) will live under this
directory, so it survives container deletion and is directly accessible from the
host (e.g., for flashing images).

## 2. Build the container image

Run from this `docker/` directory. The build arguments map your host user into the
container, so files created on the shared volume keep correct ownership:

```bash
docker build \
  --build-arg UNAME=$(whoami) \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t ubuntu-$(whoami) .
```

## 3. Create and enter the container

```bash
docker run -it \
  -v $HOME/LINUX_YOCTO_RP5_TPM_ENV:/LINUX_YOCTO_RP5_TPM_ENV \
  -w /LINUX_YOCTO_RP5_TPM_ENV \
  --name rp5_tpm_build \
  ubuntu-$(whoami) /bin/bash
```

Exit with `exit`. On subsequent sessions, reuse the same container:

```bash
docker start -ai rp5_tpm_build
```

To discard and recreate it (no work is lost — everything is on the shared volume):

```bash
docker rm -f rp5_tpm_build
```

## 4. Yocto quick reference (inside the container)

```bash
cd /LINUX_YOCTO_RP5_TPM_ENV/poky
source oe-init-build-env        # sets up build/ and puts bitbake on PATH

bitbake core-image-base         # full image build

# Rebuild U-Boot after source changes:
bitbake -c cleansstate u-boot && bitbake core-image-base
```

(See [`../BUILD.md`](../BUILD.md) for obtaining the Yocto tree and layers.)

## 5. Flashing the image (on the host)

The generated image is at
`$HOME/LINUX_YOCTO_RP5_TPM_ENV/poky/build/tmp/deploy/images/raspberrypi5-uboot-tpm/`.

```bash
# Unmount any auto-mounted SD card partitions first (device name may vary):
sudo umount /dev/mmcblk0p1 /dev/mmcblk0p2

bunzip2 -c core-image-base-raspberrypi5-uboot-tpm.rootfs.wic.bz2 \
  | sudo dd of=/dev/mmcblk0 bs=4M status=progress conv=fsync
sync
```

**Warning:** double-check the target device (`lsblk`) — `dd` will overwrite it
without confirmation.

## 6. TPM smoke test (U-Boot serial console)

```
tpm2 init
tpm2 startup TPM2_SU_CLEAR
tpm2 info
tpm2 pcr_read 0 0x10000000
```

Inspect the device tree U-Boot is using:

```
fdt addr ${fdtcontroladdr}
fdt print
```
