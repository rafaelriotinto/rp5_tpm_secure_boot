# Authenticated Boot and Firmware Verification in Raspberry Pi 5

Support materials for the MSc thesis **"Authenticated Boot and Firmware Verification
in Raspberry Pi 5"** (ISEL, 2026) — a secure + measured boot chain on the Raspberry
Pi 5 using U-Boot as third-stage bootloader (BL3) and an external TPM 2.0 module.

## Boot chain

```
BL1 (BCM2712 ROM, immutable)
  └── verifies BL2 signature (OTP-stored public key hash)
BL2 (EEPROM pieeprom.bin, signed)
  └── verifies BL3 (U-Boot) signature (owner RSA-2048 key)
BL3 = U-Boot (xen-troops fork, rpi5-2024.04-xt)
  ├── drives external TPM via soft-SPI (bit-bang over RP1 GPIO)
  ├── measures kernel + DTB (SHA-256) into the TPM
  └── boots Linux
Linux
  └── TPM via /dev/tpmrm0 (tpm2-tools / tpm2-tss)
```

## Hardware

- Raspberry Pi 5 (BCM2712, Cortex-A76) — expansion header GPIO/SPI routed through
  the **RP1** companion chip (PCIe south bridge)
- **LetsTrust TPM** module (Infineon SLB9670, TPM 2.0, SPI) on the 40-pin header

## Repository layout

| Path | Contents |
|------|----------|
| `docker/` | Ubuntu 22.04 Yocto build container (Dockerfile + usage commands) |

*(More components — Yocto layer, U-Boot configuration, device tree overlays,
provisioning scripts — will be added as the work progresses.)*

## Build environment quick start

```bash
cd docker
docker build \
  --build-arg UNAME=$(whoami) \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t ubuntu-$(whoami) .

docker run -it \
  -v $HOME/LINUX_DOCKER_SHARE:/LINUX_DOCKER_SHARE \
  -w /LINUX_DOCKER_SHARE \
  --name linux_build \
  ubuntu-$(whoami) /bin/bash
```

See `docker/instructions.sh` for the full build / flash / TPM command reference.
