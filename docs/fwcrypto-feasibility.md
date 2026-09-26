# Firmware crypto service (rpi-fw-crypto) as board anchor: feasibility (2026-09-26)

Board: control board (Pi 5, 16 GB, OTP key hash NOT programmed), booted from a Raspberry Pi OS Lite
2026-09-15 test card (r12 card imaged to snapshots/pre-fwcrypto-2026-09-26/control-r12-card.img).
Bootloader updated 2025-05-08 -> 2026-09-10 (latest channel; includes fine-grained locking 2026-06-17 and
crypto in protected RAM 2026-09-10). EEPROM config preserved (BOOT_UART=1, BOOT_ORDER=0xf461,
NET_INSTALL_AT_POWER_ON=1). Tool: rpifwcrypto 20260626-1. No OTP was written.

| Test | Result |
|---|---|
| get-num-otp-keys | 1 (key id 1; id 0 -> "Key not found") |
| key 1 status | 0x00000001 DEVICE, blank (rpi-otp-private-key -c rc=1) |
| hmac / pubkey on blank key | error 6 "Key not set (all zeros)" |
| set SIGN_LOCKED | status 0x401 (DEVICE SIGN_LOCKED) |
| sign while SIGN_LOCKED | error 4 "Key is locked" (lock checked before key-set) |
| add HMAC_LOCKED | status 0xc01: locks accumulate (firmware ORs the request) |
| clear via tool | not expressible ("0" rejected); status unchanged |
| add READ_LOCKED | 0xd01; legacy raw read (rpi-otp-private-key) fails |
| after reboot | 0x00000001: all locks cleared |

Conclusion: per-key, per-operation locks take effect immediately, accumulate, cannot be removed by the
tool, and clear only on reboot. This is the property required for U-Boot to use the key once per boot
and deny it to Linux (including root) until the next reboot.

Not yet tested (requires generating the key = irreversible, single slot):
signing from U-Boot at boot; ECDSA P-256 signature accepted by TPM2_PolicySigned on the SLB9670.
