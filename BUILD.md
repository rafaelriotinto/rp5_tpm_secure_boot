# Building the RPi5 Secure/Measured Boot Image from Scratch

These instructions reproduce the complete build environment and produce a
flashable SD card image for the Raspberry Pi 5 with U-Boot as third-stage
bootloader (BL3) and external TPM support.

All host-side steps were validated on Ubuntu-family Linux; the build itself
runs inside a Docker container (see [`docker/README.md`](docker/README.md)),
so the host distribution barely matters.

## 1. Create the work directory

All sources and build artifacts live under a single directory, bind-mounted
into the build container at the same path:

```bash
mkdir -p $HOME/LINUX_YOCTO_RP5_TPM_ENV
cd $HOME/LINUX_YOCTO_RP5_TPM_ENV
```

Expect ~150 GB of usage after a full build.

## 2. Fetch the sources

Yocto **Scarthgap** (5.0) plus the BSP and support layers, pinned to the
revisions this work was validated with:

```bash
git clone --branch scarthgap https://git.yoctoproject.org/poky
git -C poky checkout d71d81814adae2c51fdaf42f62c146041545c7fd

git clone --branch scarthgap https://git.yoctoproject.org/meta-raspberrypi poky/meta-raspberrypi
git -C poky/meta-raspberrypi checkout cd677051d18d4af2f043ac1ab58509ae5f594cf6

git clone --branch scarthgap https://git.openembedded.org/meta-openembedded poky/meta-openembedded
git -C poky/meta-openembedded checkout 7a5075cef77b5f7af454e9868e1d0019f2fd1394

git clone --branch scarthgap https://git.yoctoproject.org/meta-security poky/meta-security
git -C poky/meta-security checkout 97e482b71688b62ac1109d16e89368122f039cbf
```

This repository (provides the `meta-rpi5-uboot-tpm` layer):

```bash
git clone https://github.com/rafaelriotinto/rp5_tpm_secure_boot.git
```

The U-Boot sources (fork of `xen-troops/u-boot` with RP1 support and this
project's TPM work) are fetched automatically by BitBake from
`https://github.com/rafaelriotinto/u-boot` — no manual clone is needed for a
regular build. Clone it only if you intend to modify U-Boot (see step 6):

```bash
git clone --branch rpi5-fwcrypto https://github.com/rafaelriotinto/u-boot.git u-boot
```

## 3. Build container

Build and start the container as described in
[`docker/README.md`](docker/README.md), mounting the work directory:

```bash
cd rp5_tpm_secure_boot/docker
docker build \
  --build-arg UNAME=$(whoami) --build-arg UID=$(id -u) --build-arg GID=$(id -g) \
  -t ubuntu-$(whoami) .

docker run -it \
  -v $HOME/LINUX_YOCTO_RP5_TPM_ENV:/LINUX_YOCTO_RP5_TPM_ENV \
  -w /LINUX_YOCTO_RP5_TPM_ENV \
  --name rp5_tpm_build \
  ubuntu-$(whoami) /bin/bash
```

## 4. Configure the build (inside the container)

```bash
cd /LINUX_YOCTO_RP5_TPM_ENV/poky
source oe-init-build-env      # creates build/ on first run
```

Add the layers to `build/conf/bblayers.conf` so that `BBLAYERS` reads:

```bitbake
BBLAYERS ?= " \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-poky \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-yocto-bsp \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-raspberrypi \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-openembedded/meta-oe \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-openembedded/meta-python \
  /LINUX_YOCTO_RP5_TPM_ENV/poky/meta-security/meta-tpm \
  /LINUX_YOCTO_RP5_TPM_ENV/rp5_tpm_secure_boot/meta-rpi5-uboot-tpm \
  "
```

Append to `build/conf/local.conf`:

```bitbake
# Target machine (extends raspberrypi5 with U-Boot-as-BL3 + TPM overlays)
MACHINE = "raspberrypi5-uboot-tpm"

# systemd as init system
INIT_MANAGER = "systemd"

# Required by meta-raspberrypi (WiFi/BT firmware license)
LICENSE_FLAGS_ACCEPTED = "synaptics-killswitch"

# Boot through U-Boot instead of jumping directly to the kernel
RPI_USE_U_BOOT = "1"

# TPM 2.0 userspace (tpm2-tools + TSS) and supporting utilities
DISTRO_FEATURES:append = " tpm2"
IMAGE_INSTALL:append = " file binutils tpm2-tools tpm2-tss libtss2-tcti-device tpm2-tools-env"

# config.txt extras
RPI_EXTRA_CONFIG = "enable_uart=0"

# SSH access for development (lab bench only: together with debug-tweaks this
# gives passwordless root over the network -- do not use outside the lab)
EXTRA_IMAGE_FEATURES += "ssh-server-dropbear"
```

Networking note: no extra configuration is needed for wired Ethernet — the
image ships systemd-networkd with a default DHCP-on-Ethernet config
(`80-wired.network`), so the board obtains a lease as soon as it is cabled.

## 5. Build the image

```bash
bitbake core-image-base
```

The first build compiles everything from source and takes several hours.
The result:

```
build/tmp/deploy/images/raspberrypi5-uboot-tpm/core-image-base-raspberrypi5-uboot-tpm.rootfs.wic.bz2
```

Flash it to an SD card as described in [`docker/README.md`](docker/README.md),
then validate the TPM from the U-Boot serial console (`tpm2 init`,
`tpm2 startup TPM2_SU_CLEAR`, `tpm2 info`).

## 6. Optional: local U-Boot development

BitBake normally fetches U-Boot from the pinned fork revision. To iterate on
a local checkout instead (cloned in step 2), append to `build/conf/local.conf`:

```bitbake
INHERIT += "externalsrc"
EXTERNALSRC:pn-u-boot = "/LINUX_YOCTO_RP5_TPM_ENV/u-boot"
```

Then after each source change:

```bash
bitbake -c cleansstate u-boot && bitbake core-image-base
```

## 7. Host tools: signing, provisioning and operation

Everything after the image build -- signing releases, updating the bootloader,
programming OTP, provisioning the TPM, attestation and updates -- runs on the
host, not in the container. The Python scripts use only the standard library.

```bash
sudo apt install openssl openssh-client mtools dosfstools xxd bzip2 \
                 libusb-1.0-0-dev pkg-config build-essential

cd $HOME/LINUX_YOCTO_RP5_TPM_ENV
git clone --recurse-submodules https://github.com/raspberrypi/usbboot.git
git -C usbboot checkout e50a709 && git -C usbboot submodule update
make -C usbboot            # builds rpiboot (bootloader update, OTP programming)
```

| Tool | Used by |
|---|---|
| `usbboot/tools/rpi-make-boot-image` (`mkfs.fat`, `mcopy`) | `make-release.py`, `tamper-release.py` |
| `usbboot/tools/rpi-eeprom-digest`, `update-pieeprom.sh` (`openssl`, `xxd`) | release signing, bootloader update |
| `usbboot/rpiboot` | bootloader update and OTP programming over USB (RPIBOOT mode) |
| `openssl` | release signing, attestation verifier |
| `ssh` | `rp5.py`, attestation verifier |
| `sfdisk`, `mcopy` | `inject-boot.sh` |
| `docker` | `build-factory-uboot.sh` |

### Keys and secrets

All under `$HOME/LINUX_YOCTO_RP5_TPM_ENV/secure-boot-keys/` (never committed;
keep an encrypted offline backup of the first two):

| File | Purpose | Generate with |
|---|---|---|
| `private.pem` | owner RSA-2048 signing key; its SHA-256 hash is what the OTP burn programs | `openssl genrsa -out private.pem 2048` |
| `factory-master.bin` | factory master for the TPM hierarchy authorisations (`factory-auths.py`) | `head -c 32 /dev/urandom > factory-master.bin; chmod 600 factory-master.bin` |
| `ssh/{attest,ota,provision}_ed25519` | one client key per device service | `ssh-keygen -t ed25519 -N '' -f ssh/<service>_ed25519` |

The device holds only the public halves of the service keys: copy each
`ssh/<service>_ed25519.pub` into
`meta-rpi5-uboot-tpm/recipes-core/rp5-agents/files/authorized_keys.<service>`
(keeping the `command=...,no-port-forwarding,...` options already there) **before** building
the image. Losing `private.pem` after the OTP burn leaves the board without any
means of update; losing `factory-master.bin` prevents re-deriving the TPM owner,
endorsement and lockout authorisations.

Operation (provisioning, attestation, updates): [`agents/README.md`](agents/README.md).
