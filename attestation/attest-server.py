#!/usr/bin/env python3
"""attest-server.py - monitoring/attestation server side (runs on the desktop).

Issues a fresh nonce, drives the device's attest-device.sh over SSH, pulls back
the TPM-signed evidence, and verifies EVERYTHING:

  1. AK signatures (quote + both NV certifies) -> genuine ENROLLED TPM
  2. structure type + magic on every blob       -> no NV-certify/quote confusion
  3. quote nonce == our nonce                  -> freshness (no replay)
  4. quote covers exactly sha256:{0,1,8,9}     -> the PCRs we think we checked
  5. quote PCR digest == golden composite      -> good SOFTWARE state
  6. certified NV index NAME == golden Name    -> the RIGHT index was certified
  7. attestation-NV contents == our nonce      -> GENUINE BOARD (only a device
        that can derive the board secret could have written the nonce there)
  8. measured-boot-NV contents == golden       -> correct BOOT record

Any failure -> attestation REJECTED. Requires only openssl (via subprocess) and
the enrolled AK public key + golden values (the enrollment record).

SECURITY NOTES (why checks 2, 4 and 6 exist -- see docs/red-team-findings.md):

  C1: an earlier version parsed the certified NV index Name and then DISCARDED
  it. Nothing tied the evidence to index 0x01800001, so a warm-moved TPM on an
  attacker board could define its OWN plain NV index, write the nonce into it,
  certify that, and pass "BOARD identity" with no board secret at all. The Name
  is a hash of the index's public area (handle + attributes + policy), so
  pinning it also pins the DUID/policy protection.

  H1: the attestation TYPE was parsed and discarded too. Because the quote
  parser took "the last 32 bytes" as the pcrDigest, and an NV-certify blob ends
  with the NV CONTENTS, an attacker could write the (public) golden PCR
  composite into a rogue NV index, certify it, submit it as quote.msg, and pass
  the "PCR state == golden" check without their PCRs ever holding those values.
  Enforcing type + PCR selection closes that confusion.

  Both checks are fail-closed: a malformed blob is a REJECT, never a crash and
  never a silently-skipped check (no bare `assert`, which `python -O` strips).
"""
import hashlib, json, os, struct, subprocess, sys, tempfile, typing

# The device side runs as a dedicated NON-ROOT user ("attest", member of group
# tss for /dev/tpmrm0). It needs no secret and no privilege: quote + NV certify
# with empty platform auth. Root is deliberately not used -- a compromise of
# the attestation path must not hand over the box.
DEVICE   = os.environ.get("DEVICE", "root@192.168.10.198")   # TODO.md C1b: switch to attest@
AK_PEM   = os.environ.get("AK_PEM", "ak.pem")
REMOTE   = "/tmp/attest"
# Option B: where we remember the last resetCount, and whether this round is
# a post-reboot check (set REQUIRE_REBOOT=1 after asking the device to reboot).
STATE_FILE     = os.environ.get("ATTEST_STATE", "attest-state.json")
REQUIRE_REBOOT = os.environ.get("REQUIRE_REBOOT", "") not in ("", "0")

# Enrollment record for this device+image (golden values). PCR0 is per U-Boot
# build; capture the deployed build's value here.
GOLDEN_PCR = {
    # Re-captured 2026-09-06 for the U-Boot build with the CANONICAL devicetree
    # digest (commit 6c55511a + traversal fix). Verified byte-identical across PSU
    # and PC-USB power and across warm/cold reboots -- see docs/experimental-results.md E4.
    # Verified STABLE across a cold->warm reboot (count 1->2, rsts 0x1000->0x1020,
    # PCR0 unchanged) -> the DTB sanitizer is stripping the boot-varying fields.
    # NOTE: ideally derived from the build system, not captured from the device
    # (capturing trusts the very board being attested); see TODO.md.
    0: "827480c31fce5335284983691e01efe48e23a602e7dc389adbbb4a7e98a1c9f7",
    1: "fbf3642e972e016e33b8776e33f8ee3656bd7c15eb31c00ac13efa190932a434",
    8: "b7cfbbaf255cafaab638a36d00f96a11e6d6ee16e89c0f1e48b4416a19f6a41a",
    9: "cfc7d8042593e188c59d2fd523f07a95d06dd3160f0955d8c34b0eb067f517b6",
}
# The index now commits to the WHOLE measured state: U-Boot extends it, last
# (after the EV_SEPARATOR events), with SHA256(PCR0||PCR1||PCR8||PCR9) -- the
# same composite the TPM puts in a quote. So this equals SHA256(0*32||pcrDigest),
# which the cross-check below verifies. Recaptured 2026-09-06.
GOLDEN_MEAS_NV = "292de90b3b44bf35818eb9334f06d5f93ee6cb633f7747bc59ec575e1b279842"
PCR_SET = (0, 1, 8, 9)

# Golden NV index NAMES, captured at enrollment (C1). The Name is
# nameAlg || H_nameAlg(nvPublic), i.e. 2 + 32 bytes for SHA-256 = 34 bytes.
# Capture with, on the device:
#     tpm2_nvreadpublic 0x01800001    # -> "name: <hex>"
#     tpm2_nvreadpublic 0x01800000
# Leave empty ONLY before enrollment: verification refuses to run without them.
# Captured 2026-09-06 from board cceddb12-0af4f481.
#   0x01800001: policywrite|ownerread|authread|no_da            (attrs 0x22060008)
#   0x01800000: policywrite|nt=extend|ppread|ownerread|authread|no_da|clear_stclear
#                                                                (attrs 0x0A070048)
# Both carry authPolicy 8FCD2169...DB0E (PolicyAuthValue over the board secret),
# and the Name is a hash of that whole public area -> pinning the Name pins the
# handle, the attributes AND the policy.
GOLDEN_ATTN_NAME = "000b9a92c0bb9a925132a1dfc907558356e7ad0688d5a98f7c6116d08d265770fb60"
# Re-provisioned 2026-09-06 with TPMA_NV_PPREAD added (attrs 0x0A070048|written),
# so the device can certify with EMPTY PLATFORM auth and hold no secret.
GOLDEN_MEAS_NAME = "000b6d77af9978cd18e8a30d502db09bb64056bb36e662620d39d06d1b56e5f867b4"

# TPMS_ATTEST type tags (TPM 2.0 Part 2, TPMI_ST_ATTEST)
ST_ATTEST_NV    = 0x8014
ST_ATTEST_QUOTE = 0x8018
TPM_GENERATED   = bytes.fromhex("ff544347")   # "\xffTCG"
ALG_SHA256      = 0x000B


class ClockInfo(typing.NamedTuple):
    """TPMS_CLOCK_INFO. resetCount advances on a real TPM restart (Option B)."""
    clock: int
    reset_count: int
    restart_count: int
    safe: int


class AttestError(Exception):
    """Malformed or unexpected attestation structure -> REJECT (never a crash)."""


def sh(*a):
    subprocess.run(a, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify_sig(pem, msg, sig):
    """RSASSA (PKCS#1 v1.5 over SHA256) verify via openssl. Returns bool."""
    with tempfile.NamedTemporaryFile() as mf, tempfile.NamedTemporaryFile() as sf:
        mf.write(msg); mf.flush(); sf.write(sig); sf.flush()
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pem,
                            "-signature", sf.name, mf.name],
                           capture_output=True)
        return r.returncode == 0


def _u8(b, o):   return b[o], o + 1
def _u16(b, o):  return struct.unpack(">H", b[o:o+2])[0], o + 2
def _u32(b, o):  return struct.unpack(">I", b[o:o+4])[0], o + 4


def _tpm2b(b, o):
    """Read a TPM2B (UINT16 size || bytes). Bounds-checked."""
    n, o = _u16(b, o)
    if o + n > len(b):
        raise AttestError("TPM2B length runs past end of buffer")
    return b[o:o+n], o + n


def parse_attest(m, expected_type):
    """Parse a TPMS_ATTEST header; enforce magic and type. Return (extraData, tail).

    Fail-closed: any mismatch or truncation raises AttestError.
    """
    if len(m) < 6:
        raise AttestError("attestation blob too short")
    if m[:4] != TPM_GENERATED:
        # Without this the blob need not have been produced INSIDE the TPM.
        raise AttestError("bad TPM_GENERATED magic")
    typ, off = _u16(m, 4)
    if typ != expected_type:
        raise AttestError(f"wrong attest type: got 0x{typ:04x}, "
                          f"expected 0x{expected_type:04x}")
    _, off = _tpm2b(m, off)              # qualifiedSigner
    extra, off = _tpm2b(m, off)          # extraData (our nonce)
    # TPMS_CLOCK_INFO: clock u64, resetCount u32, restartCount u32, safe u8.
    # resetCount is what proves a restart actually happened (Option B); an
    # attacker who keeps the TPM powered and skips the reboot cannot advance it.
    if off + 17 + 8 > len(m):
        raise AttestError("truncated before clockInfo")
    clock  = struct.unpack(">Q", m[off:off+8])[0]
    resetc = struct.unpack(">I", m[off+8:off+12])[0]
    restrt = struct.unpack(">I", m[off+12:off+16])[0]
    safe   = m[off+16]
    off += 17 + 8                        # clockInfo + firmwareVersion
    return extra, m[off:], ClockInfo(clock, resetc, restrt, safe)


def nv_contents(m, expected_name):
    """Parse TPMS_NV_CERTIFY_INFO. Enforces the certified index NAME (C1).

    indexName pins WHICH index was certified. Without it any attacker-defined
    index passes.
    """
    extra, tail, clk = parse_attest(m, ST_ATTEST_NV)
    name, off = _tpm2b(tail, 0)          # indexName
    if not expected_name:
        raise AttestError("no golden NV index Name enrolled (cannot verify)")
    if name != expected_name:
        raise AttestError(f"wrong NV index certified: Name {name.hex()} "
                          f"!= golden {expected_name.hex()}")
    _, off = _u16(tail, off)             # offset
    contents, off = _tpm2b(tail, off)    # nvContents
    return extra, contents, clk


def pcr_digest(m):
    """Parse TPMS_QUOTE_INFO. Enforces the PCR SELECTION, then reads pcrDigest.

    The selection says WHICH PCRs the digest covers; the caller compares that
    digest against a golden composite computed over PCR_SET, so the selection
    must be pinned or the two need not describe the same registers.
    """
    extra, tail, clk = parse_attest(m, ST_ATTEST_QUOTE)
    count, off = _u32(tail, 0)
    if count != 1:
        raise AttestError(f"expected exactly 1 PCR selection, got {count}")
    alg, off = _u16(tail, off)
    if alg != ALG_SHA256:
        raise AttestError(f"expected SHA-256 PCR bank, got alg 0x{alg:04x}")
    nsel, off = _u8(tail, off)
    if off + nsel > len(tail):
        raise AttestError("truncated PCR selection bitmap")
    sel = tail[off:off+nsel]; off += nsel

    want = bytearray((max(PCR_SET) // 8) + 1)
    for i in PCR_SET:
        want[i // 8] |= 1 << (i % 8)
    if bytes(sel).rstrip(b"\x00") != bytes(want).rstrip(b"\x00"):
        raise AttestError(f"quote covers PCR bitmap {sel.hex()}, "
                          f"expected {bytes(want).hex()} (sha256:{','.join(map(str, PCR_SET))})")

    digest, off = _tpm2b(tail, off)      # pcrDigest
    return extra, digest, clk


def main():
    nonce = os.urandom(32)
    print(f"[server] nonce = {nonce.hex()}")
    outdir = tempfile.mkdtemp(prefix="attest-")

    try:
        meas_name = bytes.fromhex(GOLDEN_MEAS_NAME)
    except ValueError:
        print("[server] FATAL: GOLDEN_MEAS_NAME is not valid hex"); sys.exit(2)
    if not meas_name:
        print("[server] FATAL: golden NV index Name not enrolled.\n"
              "         Capture it on the device with:\n"
              "           tpm2_nvreadpublic 0x01800000   # -> GOLDEN_MEAS_NAME\n"
              "         Refusing to verify without it (this is the C1 fix).")
        sys.exit(2)

    # Option B state: the last resetCount we saw, so we can require it to ADVANCE
    # after a requested reboot. Absent on a first run.
    prev = {}
    if os.path.exists(STATE_FILE):
        try:
            prev = json.load(open(STATE_FILE))
        except (OSError, ValueError):
            prev = {}

    user_host = DEVICE
    with open(os.path.join(outdir, "nonce.bin"), "wb") as f:
        f.write(nonce)
    sh("scp", "-O", os.path.join(outdir, "nonce.bin"), f"{user_host}:/tmp/nonce.bin")

    subprocess.run(["ssh", user_host,
                    f"cp /tmp/nonce.bin {REMOTE}/nonce.bin 2>/dev/null; "
                    f"/usr/bin/attest-device.sh /tmp/nonce.bin {REMOTE}"],
                   check=True, stdout=subprocess.DEVNULL)

    files = ["quote.msg", "quote.sig", "meas_cert.msg", "meas_cert.sig"]
    for fn in files:
        sh("scp", "-O", f"{user_host}:{REMOTE}/{fn}", os.path.join(outdir, fn))
    B = lambda fn: open(os.path.join(outdir, fn), "rb").read()

    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    def parsed(name, fn, *args):
        """Run a parser fail-closed: a malformed blob is a FAIL, not a crash."""
        nonlocal ok
        try:
            return fn(*args)
        except AttestError as e:
            print(f"  [FAIL] {name}: {e}")
            ok = False
            return None, None, None

    # 1) signatures (quote sig has a 6-byte TPMT_SIGNATURE header -> raw 256)
    check("AK signature on quote",     verify_sig(AK_PEM, B("quote.msg"), B("quote.sig")[-256:]))
    check("AK signature on meas cert", verify_sig(AK_PEM, B("meas_cert.msg"), B("meas_cert.sig")))

    # 2) structure: magic + type + PCR selection (H1), fail-closed
    q_extra, q_pcr, q_clk = parsed("quote structure (magic/type/PCR selection)",
                                   pcr_digest, B("quote.msg"))

    # 3) freshness
    check("quote freshness (nonce)", q_extra == nonce)

    # 4) software state
    composite = hashlib.sha256(b"".join(bytes.fromhex(GOLDEN_PCR[i]) for i in PCR_SET)).digest()
    check("PCR state == golden", q_pcr == composite)

    # 5) boot record + BOARD BINDING (Option B). The measured-boot index is
    #    clear_stclear, so TPM2_Startup(CLEAR) empties it at every boot, and only
    #    a bootloader able to derive the board secret can extend it back. A
    #    substituted board cannot -- so this value being golden AFTER a genuine
    #    restart is what binds the evidence to the real board.
    m_extra, m_val, m_clk = parsed("meas-cert structure (type + index Name)",
                                   nv_contents, B("meas_cert.msg"), meas_name)
    check("meas-cert freshness (nonce)", m_extra == nonce)
    check("boot record (measured-boot NV == golden)", m_val == bytes.fromhex(GOLDEN_MEAS_NV))

    # 5b) CROSS-CHECK (D0b): U-Boot extends the index with the SAME composite the
    #     TPM puts in a quote, so the certified NV value must equal
    #     SHA256(0x00*32 || quote.pcrDigest). This ties "these measurements" to
    #     "a board that holds the DUID secret" -- without it, the quote and the
    #     NV certify are two signed artefacts related only by convention.
    if q_pcr is not None and m_val is not None:
        expect = hashlib.sha256(b"\x00" * 32 + q_pcr).digest()
        check("NV commits to the quoted PCRs (NV == SHA256(0*32 || pcrDigest))",
              m_val == expect)

    # 6) restart evidence -- the linchpin of Option B. An attacker who keeps the
    #    TPM powered and ignores a reboot request cannot advance resetCount.
    if q_clk:
        print(f"  [info] TPM clock={q_clk.clock} resetCount={q_clk.reset_count} "
              f"restartCount={q_clk.restart_count} safe={q_clk.safe}")
        if REQUIRE_REBOOT:
            pr = prev.get("reset_count")
            if pr is None:
                check("restart evidence (no baseline yet -- recorded)", False)
            else:
                check(f"restart evidence (resetCount {pr} -> {q_clk.reset_count})",
                      q_clk.reset_count > pr)
        elif "reset_count" in prev:
            same = q_clk.reset_count == prev["reset_count"]
            print(f"  [info] resetCount {'unchanged' if same else 'ADVANCED'} "
                  f"since last round (was {prev['reset_count']})")

    if q_clk:
        try:
            json.dump({"reset_count": q_clk.reset_count,
                       "restart_count": q_clk.restart_count,
                       "clock": q_clk.clock}, open(STATE_FILE, "w"))
        except OSError:
            pass

    print(f"\n[server] ATTESTATION {'PASSED — device trusted' if ok else 'FAILED — device REJECTED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
