#!/usr/bin/env python3
"""attest-server.py - monitoring/attestation server side (runs on the desktop).

Issues a fresh nonce, drives the device's attest-device.sh over SSH, pulls back
the TPM-signed evidence, and verifies EVERYTHING:

  1. AK signatures (quote + both NV certifies) -> genuine ENROLLED TPM
  2. quote nonce == our nonce                  -> freshness (no replay)
  3. quote PCR digest == golden composite      -> good SOFTWARE state
  4. attestation-NV contents == our nonce      -> GENUINE BOARD (only a device
        that can derive the DUID secret could have written the nonce there)
  5. measured-boot-NV contents == golden       -> correct BOOT record

Any failure -> attestation REJECTED. Requires only openssl (via subprocess) and
the enrolled AK public key + golden values (the enrollment record).
"""
import hashlib, os, struct, subprocess, sys, tempfile

DEVICE   = os.environ.get("DEVICE", "root@192.168.10.198")
AK_PEM   = os.environ.get("AK_PEM", "ak.pem")
REMOTE   = "/tmp/attest"

# Enrollment record for this device+image (golden values). PCR0 is per U-Boot
# build; capture the deployed build's value here.
GOLDEN_PCR = {
    0: "272e5eeac065135d42fdd5ee19734fde2ba094cbb23d7126f228988e1c2de51d",
    1: "fbf3642e972e016e33b8776e33f8ee3656bd7c15eb31c00ac13efa190932a434",
    8: "b7cfbbaf255cafaab638a36d00f96a11e6d6ee16e89c0f1e48b4416a19f6a41a",
    9: "cfc7d8042593e188c59d2fd523f07a95d06dd3160f0955d8c34b0eb067f517b6",
}
GOLDEN_MEAS_NV = "b7cfbbaf255cafaab638a36d00f96a11e6d6ee16e89c0f1e48b4416a19f6a41a"
PCR_SET = (0, 1, 8, 9)


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


def parse_attest(m):
    """Parse a TPMS_ATTEST: return (type, extraData, tail_bytes)."""
    assert m[:4] == bytes.fromhex("ff544347"), "bad TPM attest magic"
    typ = struct.unpack(">H", m[4:6])[0]
    off = 6
    qs = struct.unpack(">H", m[off:off+2])[0]; off += 2 + qs      # qualifiedSigner
    ed = struct.unpack(">H", m[off:off+2])[0]
    extra = m[off+2:off+2+ed]; off += 2 + ed                      # extraData (nonce)
    off += 17 + 8                                                 # clock + fwVersion
    return typ, extra, m[off:]


def nv_contents(m):
    _, extra, tail = parse_attest(m)
    off = 0
    inl = struct.unpack(">H", tail[off:off+2])[0]; off += 2 + inl # indexName
    off += 2                                                      # offset
    cl = struct.unpack(">H", tail[off:off+2])[0]
    return extra, tail[off+2:off+2+cl]


def pcr_digest(m):
    """The pcrDigest is the trailing TPM2B of a quote message."""
    _, extra, tail = parse_attest(m)
    # tail = TPML_PCR_SELECTION + TPM2B pcrDigest; the digest is the last TPM2B
    dl = struct.unpack(">H", m[-34:-32])[0]
    return extra, m[-dl:]


def main():
    nonce = os.urandom(32)
    print(f"[server] nonce = {nonce.hex()}")
    outdir = tempfile.mkdtemp(prefix="attest-")

    user_host = DEVICE
    with open(os.path.join(outdir, "nonce.bin"), "wb") as f:
        f.write(nonce)
    sh("scp", "-O", os.path.join(outdir, "nonce.bin"), f"{user_host}:/tmp/nonce.bin")

    # Run the device script (assumes attest-device.sh already on the device)
    subprocess.run(["ssh", user_host,
                    f"cp /tmp/nonce.bin {REMOTE}/nonce.bin 2>/dev/null; "
                    f"/usr/bin/attest-device.sh /tmp/nonce.bin {REMOTE}"],
                   check=True, stdout=subprocess.DEVNULL)

    files = ["quote.msg", "quote.sig", "attn_cert.msg", "attn_cert.sig",
             "meas_cert.msg", "meas_cert.sig"]
    for fn in files:
        sh("scp", "-O", f"{user_host}:{REMOTE}/{fn}", os.path.join(outdir, fn))
    B = lambda fn: open(os.path.join(outdir, fn), "rb").read()

    ok = True

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        ok = ok and cond

    # 1) signatures (quote sig has a 6-byte TPMT_SIGNATURE header -> raw 256)
    check("AK signature on quote",     verify_sig(AK_PEM, B("quote.msg"), B("quote.sig")[-256:]))
    check("AK signature on attn cert", verify_sig(AK_PEM, B("attn_cert.msg"), B("attn_cert.sig")))
    check("AK signature on meas cert", verify_sig(AK_PEM, B("meas_cert.msg"), B("meas_cert.sig")))

    # 2) freshness: nonce echoed in quote and both certifies
    q_extra, q_pcr = pcr_digest(B("quote.msg"))
    check("quote freshness (nonce)", q_extra == nonce)

    # 3) software state: PCR composite matches golden
    composite = hashlib.sha256(b"".join(bytes.fromhex(GOLDEN_PCR[i]) for i in PCR_SET)).digest()
    check("PCR state == golden", q_pcr == composite)

    # 4) board identity: attestation NV index == our nonce
    a_extra, a_val = nv_contents(B("attn_cert.msg"))
    check("attn-cert freshness (nonce)", a_extra == nonce)
    check("BOARD identity (nonce in DUID-protected index)", a_val == nonce)

    # 5) boot record: measured-boot NV index == golden
    m_extra, m_val = nv_contents(B("meas_cert.msg"))
    check("meas-cert freshness (nonce)", m_extra == nonce)
    check("boot record (measured-boot NV == golden)", m_val == bytes.fromhex(GOLDEN_MEAS_NV))

    print(f"\n[server] ATTESTATION {'PASSED — device trusted' if ok else 'FAILED — device REJECTED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
