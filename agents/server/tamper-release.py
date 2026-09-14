#!/usr/bin/env python3
"""Make deliberately bad releases for the negative tests (E2, E3).

  tamper-release.py --from <release-dir> --out <dir> --mode boot-img
      E2: flip bytes inside boot.img AFTER signing (boot.sig unchanged), manifest
      digests recomputed so the OTA service installs it. The firmware must refuse
      the signature at the trial boot and fall back to the committed pair.

  tamper-release.py --from <release-dir> --out <dir> --mode dtb --bootfs <template> [--key private.pem]
      E3: change one byte of the base devicetree inside boot.img and RE-SIGN it
      (an insider with the key). The firmware accepts it; U-Boot boots it; the
      attestation must fail on PCR0 (devicetree digest) with everything else
      passing. Also refused by the verifier if the version is unchanged? No: the
      point is that a signed-but-unexpected tree is caught by measurement.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys

ENV = os.path.expanduser("~/LINUX_YOCTO_RP5_TPM_ENV")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


ap = argparse.ArgumentParser()
ap.add_argument("--from", dest="src", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--mode", choices=["boot-img", "dtb"], required=True)
ap.add_argument("--bootfs", default=f"{ENV}/releases/bootfs-template")
ap.add_argument("--key", default=f"{ENV}/secure-boot-keys/private.pem")
ap.add_argument("--tools", default=f"{ENV}/usbboot/tools")
a = ap.parse_args()

shutil.rmtree(a.out, ignore_errors=True); shutil.copytree(a.src, a.out)
man = json.load(open(f"{a.out}/MANIFEST.json"))
if a.mode == "boot-img":
    p = f"{a.out}/boot.img"
    with open(p, "r+b") as f:
        f.seek(1 << 20); b = f.read(16); f.seek(1 << 20); f.write(bytes(x ^ 0xFF for x in b))
    man["tamper"] = "boot.img modified at offset 1 MiB after signing; boot.sig is the original"
else:
    work = f"{a.out}/bootfs"; shutil.rmtree(work, ignore_errors=True); shutil.copytree(a.bootfs, work)
    # take U-Boot and cmdline from the source release's boot.img
    for fn in ("kernel_2712.img", "cmdline.txt"):
        subprocess.check_call(["mcopy", "-o", "-i", f"{a.src}/boot.img", f"::{fn}", f"{work}/{fn}"])
    dtb = f"{work}/bcm2712-rpi-5-b.dtb"
    data = bytearray(open(dtb, "rb").read())
    # NOT /model: the firmware rewrites it from its board table before U-Boot sees the
    # tree (learned the hard way). A GPIO line name survives untouched.
    needle = b"BT_CTS\0"
    j = data.find(needle)
    assert j > 0, "gpio-line-names entry BT_CTS not found in the base devicetree"
    data[j] = ord("X")                       # "XT_CTS": one byte in rp1 gpio-line-names
    open(dtb, "wb").write(data)
    subprocess.check_call([f"{a.tools}/rpi-make-boot-image", "-d", work, "-o", f"{a.out}/boot.img", "-a", "64"], stdout=subprocess.DEVNULL)
    subprocess.check_call([f"{a.tools}/rpi-eeprom-digest", "-i", f"{a.out}/boot.img", "-o", f"{a.out}/boot.sig", "-k", a.key])
    shutil.rmtree(work)
    man["tamper"] = "base devicetree gpio-line-names entry BT_CTS->XT_CTS inside boot.img; re-signed with the owner key"
man["sha256"] = {fn: sha(f"{a.out}/{fn}") for fn in ("boot.img", "boot.sig", "rootfs.img")}
man["goldens"]["pcr0"] = None
json.dump(man, open(f"{a.out}/MANIFEST.json", "w"), indent=2)
print(json.dumps({k: man[k] for k in ("version", "tamper", "sha256")}, indent=2))
