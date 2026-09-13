"""Shared plumbing for the three device services (attestation, OTA, provisioning).

Every service is a forced command behind dropbear: the SSH channel is its
stdin/stdout, the verb comes from SSH_ORIGINAL_COMMAND (what the client asked
to run; dropbear runs the forced command instead and passes the request here).
Requests are small JSON documents or raw streams on stdin; replies are JSON on
stdout. No secret is ever read by these programs: the DUID is not in the
devicetree, and the TPM operations they perform need none.
"""
import hashlib, json, os, shlex, subprocess, sys

FW = "/proc/device-tree/chosen/bootloader"
COUNTER_INDEX = "0x01800002"
MEAS_INDEX = "0x01800000"
AK_HANDLE = "0x81010002"
BOOT_PART = {1: "/dev/mmcblk0p1", 2: "/dev/mmcblk0p2"}    # firmware partition -> boot device
ROOT_PART = {1: "/dev/mmcblk0p3", 2: "/dev/mmcblk0p4"}    # the pairing rule (mirrors U-Boot)
OTHER = {1: 2, 2: 1}
AUTOBOOT = "[all]\ntryboot_a_b=1\nboot_partition={committed}\n[tryboot]\nboot_partition={other}\n"


class Fail(Exception):
    """A refused request: reported to the client as {"ok": false, "error": ...}."""


def fw_u32(name):
    with open(os.path.join(FW, name), "rb") as f:
        return int.from_bytes(f.read(4), "big")


def fw_partition():
    return fw_u32("partition")


def fw_tryboot():
    return fw_u32("tryboot") != 0


def run(*cmd, input=None, check=True):
    r = subprocess.run(cmd, input=input, capture_output=True)
    if check and r.returncode != 0:
        raise Fail(f"{cmd[0]} failed ({r.returncode}): {r.stderr.decode(errors='replace').strip()[:300]}")
    return r.stdout


def tpm_env():
    os.environ.setdefault("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")


def counter():
    tpm_env()
    return int.from_bytes(run("tpm2_nvread", COUNTER_INDEX, "-C", "p"), "big")


def pcr(i):
    with open(f"/sys/class/tpm/tpm0/pcr-sha256/{i}") as f:
        return f.read().strip().lower()


def sha256_file(path, limit=None, bs=1 << 20):
    h = hashlib.sha256(); n = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(bs if limit is None else min(bs, limit - n))
            if not chunk:
                break
            h.update(chunk); n += len(chunk)
            if limit is not None and n >= limit:
                break
    return h.hexdigest()


def verbs():
    """(verb, args) from SSH_ORIGINAL_COMMAND, or from argv when run locally."""
    orig = os.environ.get("SSH_ORIGINAL_COMMAND")
    words = shlex.split(orig) if orig else sys.argv[1:]
    return (words[0] if words else "status"), words[1:]


def reply(**kw):
    sys.stdout.write(json.dumps(kw) + "\n"); sys.stdout.flush()


def main(handlers):
    verb, args = verbs()
    try:
        h = handlers.get(verb)
        if h is None:
            raise Fail(f"unknown verb {verb!r}; known: {', '.join(sorted(handlers))}")
        reply(ok=True, verb=verb, **(h(args) or {}))
        return 0
    except Fail as e:
        reply(ok=False, verb=verb, error=str(e)); return 1
    except Exception as e:  # never leak a traceback to the channel
        reply(ok=False, verb=verb, error=f"internal: {type(e).__name__}: {e}"); return 2
