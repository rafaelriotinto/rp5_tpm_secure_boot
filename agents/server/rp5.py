#!/usr/bin/env python3
"""Server-side CLI for the three device services.

  rp5.py status                      OTA status (active pair, counter, autoboot.txt)
  rp5.py attest                      one attestation round (attest-server.py, AGENT=1)
  rp5.py install <release-dir>       stream a release to the INACTIVE pair
  rp5.py tryboot | commit | reboot   the single steps
  rp5.py update  <release-dir>       the whole cycle: install, tryboot, wait,
                                     attest (= health check), commit, reboot, attest
  rp5.py provision <auths.json>      factory: stream the derived auths, get the record
  rp5.py enroll | verify

Environment: BOARD (host/IP, default 192.168.10.198), KEYS (dir with
attest_ed25519, ota_ed25519, provision_ed25519), REBOOT_WAIT (s, default 90).
"""
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BOARD = os.environ.get("BOARD", "192.168.10.198")
KEYS = os.environ.get("KEYS", os.path.expanduser("~/LINUX_YOCTO_RP5_TPM_ENV/secure-boot-keys/ssh"))
VERIFIER = os.path.join(HERE, "..", "..", "attestation", "attest-server.py")
WAIT = int(os.environ.get("REBOOT_WAIT", "90"))


def ssh(service, verb, stdin=None, timeout=600):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-i", f"{KEYS}/{service}_ed25519",
           f"{service}@{BOARD}", verb]
    r = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout)
    lines = r.stdout.decode(errors="replace").strip().splitlines()
    try:
        rep = json.loads(lines[-1])
    except (ValueError, IndexError):
        return {"ok": False, "error": f"no reply (rc {r.returncode}): {r.stderr.decode(errors='replace')[-300:]}"}
    return rep


def show(rep):
    print(json.dumps(rep, indent=2)); return 0 if rep.get("ok") else 1


def tar_release(d):
    import io, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for fn in ("MANIFEST.json", "boot.img", "boot.sig", "rootfs.img"):
            t.add(os.path.join(d, fn), arcname=fn)
    return buf.getvalue()


def attest():
    env = dict(os.environ, AGENT="1", AGENT_KEY=f"{KEYS}/attest_ed25519", DEVICE=f"attest@{BOARD}", REQUIRE_REBOOT="1")
    r = subprocess.run([sys.executable, VERIFIER], env=env)
    return r.returncode == 0


def wait_up():
    time.sleep(20)
    for _ in range(WAIT // 5):
        rep = ssh("attest", "status", timeout=15)
        if rep.get("ok"):
            return rep
        time.sleep(5)
    return None


def update(release):
    man = json.load(open(os.path.join(release, "MANIFEST.json")))
    print(f"[update] release version {man['version']}")
    before = ssh("ota", "status")
    if not before.get("ok"):
        print("[update] status failed:", before.get("error")); return 1
    print(f"[update] board: committed pair {before['committed']}, target {before['target']}, counter {before['counter']}")
    rep = ssh("ota", "install", stdin=tar_release(release))
    if not rep.get("ok"):
        print("[update] install REFUSED:", rep.get("error")); return 1
    print(f"[update] installed into pair {rep['target']}: {rep['verified']}")
    rep = ssh("ota", "tryboot")
    if not rep.get("ok"):
        print("[update] tryboot refused:", rep.get("error")); return 1
    print("[update] trial boot requested; waiting")
    st = wait_up()
    if not st:
        print("[update] board did not come back; the committed pair will boot on the next reset"); return 1
    print(f"[update] up: partition {st['partition']} tryboot {st['tryboot']} counter {st['counter']}")
    if not st["tryboot"] or st["partition"] != before["target"]:
        print("[update] NOT on the trial pair: the trial fell back or never happened; not committing"); return 1
    print("[update] health check = attestation round")
    if not attest():
        print("[update] attestation FAILED on the trial: not committing; a plain reboot returns to the committed pair"); return 1
    rep = ssh("ota", "commit")
    if not rep.get("ok"):
        print("[update] commit refused:", rep.get("error")); return 1
    print(f"[update] committed pair {rep['committed']}; rebooting")
    ssh("ota", "reboot")
    st = wait_up()
    if not st:
        print("[update] board did not come back after commit"); return 1
    print(f"[update] up: partition {st['partition']} tryboot {st['tryboot']} counter {st['counter']}")
    ok = attest()
    print("[update] DONE" if ok else "[update] attestation FAILED on the committed boot")
    return 0 if ok else 1


def main(argv):
    if not argv:
        print(__doc__); return 2
    v, a = argv[0], argv[1:]
    if v == "status":
        return show(ssh("ota", "status"))
    if v == "attest":
        return 0 if attest() else 1
    if v == "install":
        return show(ssh("ota", "install", stdin=tar_release(a[0])))
    if v in ("tryboot", "commit", "reboot"):
        return show(ssh("ota", v))
    if v == "update":
        return update(a[0])
    if v == "provision":
        return show(ssh("provision", "provision", stdin=open(a[0], "rb").read()))
    if v in ("enroll", "verify"):
        return show(ssh("provision", v))
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
