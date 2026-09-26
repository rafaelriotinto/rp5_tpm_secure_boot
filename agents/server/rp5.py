#!/usr/bin/env python3
"""Server-side CLI for the three device services.

  rp5.py status                      OTA status (active pair, counter, autoboot.txt)
  rp5.py attest [--require-reboot]   one attestation round (attest-server.py, AGENT=1).
                                     Passes on a good software state and REPORTS the
                                     freshness of the evidence (fresh = restarted since
                                     the last round, stale = not). With --require-reboot
                                     a stale round FAILS (used after 'reboot' and inside
                                     'update').
  rp5.py install <release-dir>       stream a release to the INACTIVE pair
  rp5.py tryboot | commit | reboot   the single steps
  rp5.py update  <release-dir>       the whole cycle: install, tryboot, wait,
                                     attest (= health check), commit, reboot, attest
  rp5.py provision <auths.json>      factory: stream the derived auths, get the record
  rp5.py provision-fwkey <auths.json> factory: firmware-key anchor (OTP key + PolicySigned indices);
                                     on an already provisioned TPM only "owner" is used
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
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", "-i", f"{KEYS}/{service}_ed25519",
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


# Per-board server state: attestation/boards/<BOARD>/{ak.pem, enrollment.json,
# current-goldens.json, attest-state.json}. The verifier is pointed at them.
BOARD_DIR = os.path.join(HERE, "..", "..", "attestation", "boards", BOARD)
os.makedirs(BOARD_DIR, exist_ok=True)
GOLDENS_CURRENT = os.path.join(BOARD_DIR, "current-goldens.json")
ENROLLMENT = os.path.join(BOARD_DIR, "enrollment.json")


def predict_pcr0(version_string, dt_digest_hex):
    """PCR0 = extend(extend(extend(0, H(version string + NUL)), H(dt digest)), H(ff ff ff ff))
    -- U-Boot measures the S-CRTM version string, then the canonical devicetree digest
    (the digest bytes are what gets hashed), then the EV_SEPARATOR."""
    import hashlib
    H = lambda b: hashlib.sha256(b).digest()
    v = H(b"\0" * 32 + H(version_string.encode() + b"\0"))
    d = H(v + H(bytes.fromhex(dt_digest_hex)))
    return H(d + H(b"\xff" * 4)).hex()
PCR9_NO_INITRD = "cfc7d8042593e188c59d2fd523f07a95d06dd3160f0955d8c34b0eb067f517b6"


def attest(goldens_file=None, require_reboot=True):
    env = dict(os.environ, AGENT="1", AGENT_KEY=f"{KEYS}/attest_ed25519", DEVICE=f"attest@{BOARD}",
               REQUIRE_REBOOT="1" if require_reboot else "0",
               AK_PEM=os.path.join(BOARD_DIR, "ak.pem"), ATTEST_STATE=os.path.join(BOARD_DIR, "attest-state.json"),
               ENROLLMENT_FILE=ENROLLMENT,
               GOLDENS_FILE=goldens_file or GOLDENS_CURRENT)
    r = subprocess.run([sys.executable, VERIFIER], env=env)
    return r.returncode == 0


def predict_pcr1(prefix, cmdline_template):
    """PCR1 = extend(extend(0, H(firmware prefix + substituted cmdline + NUL)), H(separator)),
    one value per root slot. The prefix (MAC address etc.) is enrolled per board."""
    import hashlib
    H = lambda b: hashlib.sha256(b).digest()
    out = {}
    for slot, dev in (("A", "/dev/mmcblk0p3"), ("B", "/dev/mmcblk0p4")):
        s = (prefix + cmdline_template.replace("@ROOTDEV@", dev)).encode() + b"\0"
        out[slot] = H(H(b"\0" * 32 + H(s)) + H(b"\xff" * 4)).hex()
    return out


def goldens_for(man, pcr0, release):
    g = man["goldens"]
    enr = json.load(open(ENROLLMENT)) if os.path.exists(ENROLLMENT) else {}
    pcr1 = predict_pcr1(enr["bootargs_prefix"], man["cmdline"]) if enr.get("bootargs_prefix") and man.get("cmdline") else g["pcr1"]
    return {"release": release, "pcr0": pcr0, "pcr1": pcr1, "pcr8": g["pcr8"],
            "pcr9": g.get("pcr9") or PCR9_NO_INITRD}


def wait_up():
    """Wait for the attestation service after a reboot. Returns the status reply, or a
    reply with ok=false when the board answers but cannot serve (e.g. no TPM in Linux),
    or None when it never came back."""
    time.sleep(20)
    last = None
    for _ in range(WAIT // 5):
        rep = ssh("attest", "status", timeout=15)
        if rep.get("ok"):
            return rep
        if "no reply" not in rep.get("error", ""):
            last = rep          # reachable, service answered with an error
        time.sleep(5)
    return last


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
    if not st.get("ok"):
        print(f"[update] board is up but the attestation service failed: {st.get('error')}; not committing"); return 1
    print(f"[update] up: partition {st['partition']} tryboot {st['tryboot']} counter {st['counter']}")
    if not st["tryboot"] or st["partition"] != before["target"]:
        print("[update] NOT on the trial pair: the trial fell back or never happened; not committing"); return 1
    # Goldens for the health check come from the manifest. PCR0 cannot be computed
    # on the host yet (it includes the U-Boot build stamp, E14): if the manifest
    # has none, it is taken from this trial boot and recorded -- trust on first
    # use for that ONE value; PCR1/8/9, the NV commitment, the AK signature and
    # the reset counter are all still checked against host-side values.
    # PCR0 and PCR1 are per BOARD (devicetree digest, firmware prefix): always predict
    # them from this board's enrollment; the manifest holds nothing board-specific.
    enr = json.load(open(ENROLLMENT)) if os.path.exists(ENROLLMENT) else {}
    pcr0 = None
    if enr.get("dt_digest") and man.get("uboot_version_string"):
        pcr0 = predict_pcr0(man["uboot_version_string"], enr["dt_digest"])
        print(f"[update] PCR0 predicted on the host from the enrolled devicetree digest: {pcr0[:16]}...")
    if not pcr0:
        pcr0 = st["pcr"]["0"]
        print(f"[update] no enrollment: capturing PCR0 {pcr0[:16]}... from the trial boot (TOFU)")
    if st.get("dt_digest") and not enr.get("dt_digest"):
        print(f"[update] board reports devicetree digest {st['dt_digest'][:16]}...; run 'rp5.py enroll-dt' to record it")
    gfile = os.path.join(release, "goldens.json")
    json.dump(goldens_for(man, pcr0, os.path.basename(os.path.abspath(release))), open(gfile, "w"), indent=2)
    print("[update] health check = attestation round")
    if not attest(gfile):
        print("[update] attestation FAILED on the trial: not committing; a plain reboot returns to the committed pair"); return 1
    rep = ssh("ota", "commit")
    if not rep.get("ok"):
        print("[update] commit refused:", rep.get("error")); return 1
    print(f"[update] committed pair {rep['committed']}; rebooting")
    ssh("ota", "reboot")
    st = wait_up()
    if not st or not st.get("ok"):
        print(f"[update] board did not come back cleanly after commit: {st and st.get('error')}"); return 1
    print(f"[update] up: partition {st['partition']} tryboot {st['tryboot']} counter {st['counter']}")
    ok = attest(gfile)
    if ok:
        import shutil; shutil.copy(gfile, GOLDENS_CURRENT)
        print(f"[update] goldens of release {man['version']} are now current ({GOLDENS_CURRENT})")
    print("[update] DONE" if ok else "[update] attestation FAILED on the committed boot")
    return 0 if ok else 1


def main(argv):
    if not argv:
        print(__doc__); return 2
    v, a = argv[0], argv[1:]
    if v == "status":
        return show(ssh("ota", "status"))
    if v == "attest":
        return 0 if attest(require_reboot="--require-reboot" in a) else 1
    if v == "install":
        return show(ssh("ota", "install", stdin=tar_release(a[0])))
    if v in ("tryboot", "commit", "reboot"):
        return show(ssh("ota", v))
    if v == "update":
        return update(a[0])
    if v in ("enroll", "provision", "provision-fwkey"):
        rep = ssh("provision", v, stdin=open(a[0], "rb").read() if v != "enroll" else None)
        if rep.get("ok") and rep.get("ak_pem"):
            enr = json.load(open(ENROLLMENT)) if os.path.exists(ENROLLMENT) else {}
            enr.update({k: rep[k] for k in ("dt_digest", "meas_index", "meas_name", "counter_index", "counter_name", "counter",
                                            "anchor", "fw_pubkey_der", "fw_key_name", "meas_policy", "counter_policy") if k in rep})
            enr["board"] = BOARD
            json.dump(enr, open(ENROLLMENT, "w"), indent=2)
            open(os.path.join(BOARD_DIR, "ak.pem"), "w").write(rep["ak_pem"])
            print(f"[{v}] enrollment record and AK saved under {BOARD_DIR}")
        return show(rep)
    if v == "verify":
        return show(ssh("provision", v, stdin=open(ENROLLMENT, "rb").read() if os.path.exists(ENROLLMENT) else None))
    if v == "enroll-dt":
        # record the board's canonical devicetree digest (from the unprivileged status;
        # the provisioning record carries it too) so PCR0 can be predicted per release
        st = ssh("attest", "status")
        if not st.get("ok") or not st.get("dt_digest"):
            print("board reports no devicetree digest (release < r9?)"); return 1
        enr = json.load(open(ENROLLMENT)) if os.path.exists(ENROLLMENT) else {}
        enr.update({"board": BOARD, "dt_digest": st["dt_digest"], "captured_pcr0": st["pcr"]["0"]})
        if st.get("bootargs") and "dwc_otg" in st["bootargs"]:
            enr["bootargs_prefix"] = st["bootargs"][:st["bootargs"].find("dwc_otg")]
        json.dump(enr, open(ENROLLMENT, "w"), indent=2); print(json.dumps(enr, indent=2)); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
