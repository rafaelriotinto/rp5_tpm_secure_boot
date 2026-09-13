#!/usr/bin/env python3
"""Assemble a signed release directory from the Yocto deploy directory.

  make-release.py --version N --out <dir> [--deploy <dir>] [--key private.pem]
                  [--bootfs <template dir>] [--uboot u-boot.bin]

Produces: boot.img (rpi-make-boot-image over the bootfs template with the
deployed U-Boot as kernel_2712.img and a cmdline.txt derived from the deployed
verity image), boot.sig, rootfs.img (the .ext4.verity), MANIFEST.json with
digests, the version, and the goldens the host can compute (PCR1 per slot,
PCR8). PCR0 is captured at the first boot of the release (it includes the
U-Boot build stamp; see experimental-results.md E14).

The cmdline template: dm-mod.create over @ROOTDEV@ with hash_start =
DATA_SIZE/4096 + 1 (veritysetup superblock), the formula proven in
provisioning/verity/verity-cmdline.sh.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys

H = lambda b: hashlib.sha256(b).digest()
ENV = os.path.expanduser("~/LINUX_YOCTO_RP5_TPM_ENV")
FW_PREFIX = (b"reboot=w coherent_pool=1M 8250.nr_uarts=1 pci=pcie_bus_safe cgroup_disable=memory "
             b"numa_policy=interleave bcm2708_fb.fbwidth=640 bcm2708_fb.fbheight=480 bcm2708_fb.fbdepth=16 "
             b"bcm2708_fb.fbswap=1 numa=fake=4 system_heap.max_order=0 iommu_dma_numa_policy=interleave "
             b"smsc95xx.macaddr=88:A2:9E:82:BB:4D vc_mem.mem_base=0x3fc00000 vc_mem.mem_size=0x40000000  ")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--deploy", default=f"{ENV}/poky/build/tmp/deploy/images/raspberrypi5-uboot-tpm")
    ap.add_argument("--key", default=f"{ENV}/secure-boot-keys/private.pem")
    ap.add_argument("--bootfs", required=True, help="template boot tree (config.txt, dtbs, overlays, Image)")
    ap.add_argument("--uboot", default=None)
    ap.add_argument("--tools", default=f"{ENV}/usbboot/tools")
    a = ap.parse_args()

    verity = os.path.realpath(f"{a.deploy}/core-image-base-raspberrypi5-uboot-tpm.rootfs.ext4.verity")
    env = {}
    envf = verity + ".env"
    if not os.path.exists(envf):   # meta-security keeps it in work-shared, not deploy
        envf = f"{ENV}/poky/build/tmp/work-shared/raspberrypi5-uboot-tpm/dm-verity/core-image-base.ext4.verity.env"
    for line in open(envf):
        if "=" in line:
            k, v = line.strip().split("=", 1); env[k] = v.strip('"')
    data_size = int(env["DATA_SIZE"]); hbs = int(env["HASH_BLOCK_SIZE"]); dbs = int(env["DATA_BLOCK_SIZE"])
    sectors = data_size // 512; hash_start = data_size // hbs + 1
    cmdline = (f'dwc_otg.lpm_enable=0 dm-mod.create="vroot,,,ro,0 {sectors} verity 1 @ROOTDEV@ @ROOTDEV@ '
               f'{dbs} {hbs} {env["DATA_BLOCKS"]} {hash_start} {env["HASH_ALGORITHM"]} {env["ROOT_HASH"]} {env["SALT"]}" '
               f'dm-mod.waitfor=@ROOTDEV@ root=/dev/dm-0 rootfstype=ext4 rootwait ro net.ifnames=0')

    os.makedirs(a.out, exist_ok=True)
    work = os.path.join(a.out, "bootfs"); shutil.rmtree(work, ignore_errors=True); shutil.copytree(a.bootfs, work)
    shutil.copy(a.uboot or f"{a.deploy}/u-boot.bin", f"{work}/kernel_2712.img")
    shutil.copy(f"{a.deploy}/Image", f"{work}/Image") if os.path.exists(f"{a.deploy}/Image") else None
    open(f"{work}/cmdline.txt", "w").write(cmdline + "\n")
    subprocess.run([f"{a.tools}/rpi-make-boot-image", "-d", work, "-o", f"{a.out}/boot.img", "-a", "64"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([f"{a.tools}/rpi-eeprom-digest", "-i", f"{a.out}/boot.img", "-o", f"{a.out}/boot.sig", "-k", a.key], check=True)
    shutil.copy(verity, f"{a.out}/rootfs.img")
    shutil.rmtree(work)

    image = open(f"{a.bootfs}/Image", "rb").read() if os.path.exists(f"{a.bootfs}/Image") else open(f"{a.deploy}/Image", "rb").read()
    pcr1 = {}
    for slot, dev in (("A", b"/dev/mmcblk0p3"), ("B", b"/dev/mmcblk0p4")):
        s = FW_PREFIX + cmdline.encode().replace(b"@ROOTDEV@", dev) + b"\0"
        pcr1[slot] = H(H(b"\0" * 32 + H(s)) + H(b"\xff" * 4)).hex()
    uboot = open(a.uboot or f"{a.deploy}/u-boot.bin", "rb").read()
    import re
    ver = re.search(rb"U-Boot 2024\.04 \([^)]*\)", uboot)
    man = {"version": a.version, "cmdline": cmdline,
           "sha256": {fn: sha(f"{a.out}/{fn}") for fn in ("boot.img", "boot.sig", "rootfs.img")},
           "rootfs": {"root_hash": env["ROOT_HASH"], "size": os.path.getsize(f"{a.out}/rootfs.img")},
           "uboot_version_string": ver.group(0).decode() if ver else None,
           "goldens": {"pcr0": None, "pcr1": pcr1, "pcr8": H(b"\0" * 32 + H(image)).hex()}}
    json.dump(man, open(f"{a.out}/MANIFEST.json", "w"), indent=2)
    print(json.dumps(man, indent=2))


if __name__ == "__main__":
    main()
