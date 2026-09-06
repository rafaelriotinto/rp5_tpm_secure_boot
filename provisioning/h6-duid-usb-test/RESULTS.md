# H6 — Does the burned board disclose the DUID over USB (RPIBOOT)?

**Executed 2026-09-06.** Settles the question left open in `provisioning-design.md` §3c,
which was explicitly marked *"HYPOTHESIS (NOT yet validated — do not state as fact)"*.

## Method

Identical command, identical host, identical payload, run against two boards that differ
**only** in whether the OTP customer key hash has been burned:

```
sudo ./run-h6.sh <label> -d mass-storage-gadget64
```

`mass-storage-gadget64` is an **unsigned, host-supplied second stage**. It is exactly what a
physical attacker would use: it boots the board into a USB mass-storage gadget with full
hardware access — the same execution context that reads OTP and reports `FACTORY_UUID`.

Two independent detectors: `rpiboot -v` (every message the device sends) and `dumpcap` on
`usbmon0` (the raw wire, independent of rpiboot's own code paths).

## Results

| | **E0 — 16 GB, UNBURNED** (control) | **E1 — 1 GB, BURNED** |
|---|---|---|
| `bootcode5.bin` executed | **YES** | **NO** |
| File requests from device | 21 (`mcb.bin`, `memsys0*.bin`, `rp1c0fw*.bin`, `bootmain`, `config.txt`, `boot.img`) | **0** |
| Final USB ID | `0a5c:0104` (gadget) | `0a5c:2712` (still ROM boot) |
| USB block device | `sda`, 29.5 GB | **none** |
| `rpiboot` exit | 0 | 124 (timeout) |
| `FACTORY_UUID` on the wire | 0 | 0 |

E1 log, the decisive lines:

```
Sending bootcode.bin
libusb_bulk_transfer sent 78332 bytes; returned 0   <- ROM ACCEPTED the transfer
Successful read 4 bytes
Waiting for BCM2835/6/7/2711/2712...                <- device reset; did NOT execute it
Sending bootcode.bin
Failed control transfer (-7,24)                     <- then loops indefinitely
```

The ROM accepts the bytes and then refuses to run them, resetting instead. The board never
reaches the file-server phase, so no second stage ever runs.

## Conclusion

**The RPIBOOT arbitrary-code-execution path is CLOSED by the OTP burn.** An attacker with
physical USB access cannot run their own code on the provisioned board, and therefore cannot
use that channel to read OTP and extract the DUID.

This confirms the §3c hypothesis and, combined with the source review, gives the full picture:
DUID disclosure requires **executing a second stage that chooses to read OTP and report it**
(`main.c:780-810`, metadata arrives as a message filename `*FACTORY_UUID*<c40 hex words>`).
Post-burn, that second stage must be counter-signed with the customer key — which the attacker
does not have.

## Scope of the claim — state precisely, do not overclaim

**Proven:** an unsigned second stage supplied over USB does not execute on the OTP-burned
board, while the *same payload executes fully* on an unburned board. The only variable is the
burn.

**Not proven:** the absence of an undocumented ROM-level command that could disclose OTP
*without* executing a second stage. The 244 KB E1 capture contains no `FACTORY_UUID` and no
DUID digits, but the host never issues such a command, so this is a lower bound, not a proof.
The ROM is immutable and its protocol only partly documented.

**Methodological note (important):** `mass-storage-gadget64` does **not** emit `FACTORY_UUID`
even on an unburned board — DUID metadata is emitted only by the EEPROM recovery flow (both
historical JSONs in `provisioning/baseline/` come from EEPROM flashes). So "no FACTORY_UUID on
the wire" is **not** the load-bearing evidence here. The load-bearing evidence is the **refusal
to execute**: no code execution ⇒ no OTP read ⇒ no DUID report. The first attempt at this
experiment mistakenly treated the absence of metadata in this flow as meaningful; the positive
control is what caught the error.

## Consequence for the thesis

The line in §3c — *"treat the DUID and ALL OTP as physically extractable over USB,
permanently"* — is now retracted and replaced by measurement. Post-provisioning, the DUID's
confidentiality over the USB channel rests on the OTP-enforced signature check, and that check
was observed working.

Remaining DUID exposure paths (all addressed by TODO items C and D, none of them USB):
on-device root, the world-readable `/chosen/rpi-duid` DT node, `/dev/vcio` + nvmem sysfs, and
the U-Boot console.

## Reproducing

```
# control (must run FIRST; a null result is meaningless without it)
sudo ./run-h6.sh E0-16GB-unburned -d mass-storage-gadget64
# test
sudo ./run-h6.sh E1-1GB-burned    -d mass-storage-gadget64
```

Board must be in RPIBOOT mode (hold power button while connecting USB-C). The script refuses
any argument naming `secure-boot-recovery`, so it cannot flash or burn anything.

## Still open (E2/E3, lower priority now)

- **E2** — bad-signature EEPROM image, post-burn (the Aug-18 test redone under enforcement).
- **E3** — EEPROM signed with a *different* RSA key: the closest analogue to a real attacker,
  who can sign but not with our key. Both now less critical: E1 already shows the attacker
  cannot get code running at all.
