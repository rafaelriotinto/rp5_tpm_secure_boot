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

## TPM side: TPM2_PolicySigned with an ECDSA P-256 key (same test card, TPM enabled with dtoverlay=tpm-slb9670)

TPM on the control board: Infineon OPTIGA TPM **SLB 9672** (vendor strings "SLB9" "672"), firmware 15.24 (TPM2_PT_FIRMWARE_VERSION_1 0x000F0018, _2 0x004A0A00), TPM library revision 1.59, NIST P-256 and ECDSA supported. NOTE: not the SLB 9670 the thesis names; the demonstration board's TPM model has not been read out yet.
A throwaway software P-256 key stood in for the firmware key (the firmware signs a SHA-256 prehash, which is
what `openssl dgst -sha256 -sign` does). Nothing was written to OTP; the test NV index was removed afterwards.

| Test | Result |
|---|---|
| to-be-signed data | 36 bytes = nonceTPM (32) + expiration (4); tpm2-tools omits the nonce unless `-x` is given (a nonce-less signature would be replayable: the design must always include it) |
| PolicySigned, correct key, fresh nonce | accepted |
| wrong key | refused |
| session-1 signature replayed in a new session | refused (new nonce) |
| test index 0x01800010 (platform hierarchy, nt=extend, policywrite, clear_stclear, policy = PolicySigned(key)) extended with a signature bound (cpHash) to value A | accepted; content = SHA256(0^32 || A), as expected |
| signature bound to A, attempt to extend B | refused (session/policy check) |
| extend without a signature | refused (authValue or authPolicy) |

Conclusion: the SLB 9672 enforces PolicySigned with P-256 exactly as the design needs, including freshness
(nonce) and binding of the signature to the exact value written (cpHash).

## Firmware key: generated and used with the TPM (2026-09-26T12:16Z, control board, run by Rafael)

Script provisioning/fwcrypto/genkey-and-policysigned-test.sh; raw output and public key in
provisioning/fwcrypto/results-control-2026-09-26/. IRREVERSIBLE: the control board's only OTP key slot now holds
a firmware-generated ECDSA P-256 key.

| Step | Result |
|---|---|
| genkey --key-id 1 --alg ec | "Successfully generated ECDSA key in slot 1" |
| READ_LOCKED, then privkey | status 0x101; raw private key read refused |
| public key | DER SubjectPublicKeyInfo, 91 bytes (in results dir) |
| PolicySigned: firmware signs nonceTPM‖expiration (CLI hashes, firmware signs the SHA-256 digest) | TPM ACCEPTED; DER signature 71 bytes |
| openssl verification of the same signature | Verified OK |
| SIGN_LOCKED + HMAC_LOCKED, then sign | status 0xd01; sign refused, error 4 "Key is locked" |

Conclusion: the complete signing path works on the hardware: firmware-held key -> ECDSA over the TPM's fresh
nonce -> accepted by TPM2_PolicySigned on the SLB 9672; locks then deny further use until reboot.

Remaining: issue the same mailbox calls from U-Boot at boot (U-Boot already uses the property mailbox on the
Pi 5, e.g. for the memory size) and set the locks before Linux.

## U-Boot calling the firmware at boot (2026-09-26, control board)

U-Boot branch rpi5-fwcrypto (include/rpi_fwcrypto.h, board/raspberrypi/rpi/rpi_fwcrypto.c): property-mailbox
calls for key status, public key, ECDSA sign (32-byte digest) and set-lock, plus DER -> r||s conversion.
Test build with the sequence in CONFIG_PREBOOT, booted once via tryboot.txt (kernel=u-boot-fwc.bin) on the
Raspberry Pi OS test card; results written with fatwrite to the boot partition (results dir: uboot-fwctest.txt).

| Step in U-Boot | Result |
|---|---|
| key status at start of U-Boot | 0x1 (DEVICE, no locks: the earlier Linux locks were cleared by the reset) |
| public key | identical to the one read from Linux |
| sign SHA-256("u-boot rpi-fw-crypto test") | 71-byte DER signature, parsed to r‖s; verified on the host with openssl |
| lock READ/GEN/SIGN/HMAC/USAGE, read back | 0x1f01 (all five) |
| sign again | refused, firmware error 4 (Key is locked) |
| status after the next reset, from Linux | 0x1 (locks cleared) |

Conclusion: every firmware-side step the design needs works from U-Boot on the Pi 5. Remaining work is on the
TPM side of U-Boot: TPM2_LoadExternal + TPM2_PolicySigned, use of the signed session for the NV extend and the
anti-rollback increment, and provisioning of the indices with the PolicySigned policy.

## U-Boot: PolicySigned NV extend end to end (2026-09-26, control board)

U-Boot branch rpi5-fwcrypto adds TPM2_LoadExternal and TPM2_PolicySigned (lib/tpm-v2.c) and
rpi_fwc_policy_signed_session (board/raspberrypi/rpi/rpi_fwcrypto.c).

1. Key identity: U-Boot's fixed public area (P-256, sign|userWithAuth, NULL scheme) gives Name
   000b3a08…82be and, with policyRef "rp5-nv-meas-v1", policy e12aedd0…1e3b. The TPM computed the same
   Name (tpm2_loadexternal -a "sign|userwithauth") and the same trial policy digest.
2. Test index 0x01800011 (platform hierarchy, nt=extend, policywrite, no clear_stclear) defined from Linux
   with that policy.
3. Trial boot of the test U-Boot (dtoverlay=letstrust-tpm-uboot): firmware signs
   SHA256(nonceTPM ‖ 0 ‖ cpHash(NV_Extend) ‖ policyRef), PolicySigned, NV_Extend with the policy session
   (empty HMAC key): return code 0; key then locked (0x1f01). Output: results dir uboot-fwctest2.txt.
4. Read back from Linux: index = f2730db5…e0e0 = SHA256(0^32 ‖ SHA256("u-boot policysigned nv-extend test")),
   exactly as expected. Test index removed.

Conclusion: the complete board-binding path of the new design works from U-Boot on the hardware.
Next: replace the DUID-derived session in measure_nv_extend and antirollback_check (boot/bootm.c) with
rpi_fwc_policy_signed_session, lock the key before starting the kernel, provision the indices with the
PolicySigned policy, and build a release for an end-to-end test with attestation.

## Release r14 on the control board (2026-09-26)

Release r14: U-Boot rpi5-fwcrypto c4b3e0d with CONFIG_MEASURE_NV_AUTH_FWKEY=y, version 14, boot tree with
lock_device_private_key=1. Card: Yocto wic + signed r14 boot.img in both pairs (inject-boot.sh). Serial logs in
provisioning/fwcrypto/results-control-r14-2026-09-26/ (03 is two interleaved captures).

| Test | Result |
|---|---|
| First boot | U-Boot: ARB raised the counter 13 -> 14 with a firmware-signed session; NV commit OK; key locked 0x1f01 before "Starting kernel". Kernel panic: the unburned firmware booted the loose partition files (generic cmdline) because the card lacked boot_ramdisk=1 (the r12 card had it added by hand in E18). Fixed in inject-boot.sh. |
| Boot with boot_ramdisk=1 | firmware reads boot.img and its verity cmdline; version 14 == counter 14; NV commit OK (signed); key locked 0x1f01; verity root mounted; services up |
| Attestation (after re-capturing dt_digest and firmware prefix, changed by the bootloader update) | PCR0/1/8/9 equal the host predictions; NV index Name (written state, computed from the definition) matches; NV == SHA256(0^32 ‖ pcrDigest): PASSED |
| Attested reboot (rp5.py reboot, attest --require-reboot) | resetCount 165 -> 166, all checks PASSED |
| Rollback: signed r12 presented as version 14, trial-booted | r12 U-Boot: "[ARB] ROLLBACK … refusing to boot … resetting"; fallback to the committed r14 pair, which locked the key again; board on partition 1, counter 14 |

Found on the way: (1) attest-server.py checked every board against the demonstration board's index Name (the
enrollment load ran before the default was assigned), fixed; (2) enrollment must hold WRITTEN-state index Names;
(3) a bootloader update changes PCR0 and PCR1 predictions (devicetree digest, firmware command-line prefix), so
the board must be re-enrolled after a firmware update.
