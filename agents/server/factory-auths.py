#!/usr/bin/env python3
"""Factory host: derive a board's TPM auth values from the factory master and the
board's DUID, for `rp5.py provision`. The device never sees the master or the DUID.

  factory-auths.py --duid 0000911045808726 [--master <file>] --out auths.json

Derivations (all SHA256, DUID as the devicetree string INCLUDING its NUL):
  owner / endorsement / lockout = H("rp5-<h>-auth-v1" || master || DUID)   (provision-hierarchy-auth.sh)
  nv_auth      = H("rp5-nv-auth-v1"    || DUID)   (measured-boot extend index; U-Boot derives the same)
  counter_auth = H("rp5-nv-counter-v1" || DUID)   (anti-rollback counter;      U-Boot derives the same)
"""
import argparse, hashlib, json, os, stat

ap = argparse.ArgumentParser()
ap.add_argument("--duid", required=True, help="16 hex digits as shown in /chosen/rpi-duid")
ap.add_argument("--master", default=os.path.expanduser("~/LINUX_YOCTO_RP5_TPM_ENV/secure-boot-keys/factory-master.bin"))
ap.add_argument("--out", required=True)
a = ap.parse_args()
duid = a.duid.lower().encode() + b"\0"
master = open(a.master, "rb").read()
H = lambda *parts: hashlib.sha256(b"".join(parts)).hexdigest()
auths = {"owner": H(b"rp5-owner-auth-v1", master, duid),
         "endorsement": H(b"rp5-endorsement-auth-v1", master, duid),
         "lockout": H(b"rp5-lockout-auth-v1", master, duid),
         "nv_auth": H(b"rp5-nv-auth-v1", duid),
         "counter_auth": H(b"rp5-nv-counter-v1", duid)}
with open(a.out, "w") as f:
    json.dump(auths, f, indent=2)
os.chmod(a.out, stat.S_IRUSR | stat.S_IWUSR)
print(f"wrote {a.out} (owner {auths['owner'][:8]}..., nv {auths['nv_auth'][:8]}..., counter {auths['counter_auth'][:8]}...)")
