# Device services and server CLI

Three services on the device, each a **forced command behind dropbear**: one
SSH key, one user, one program. A connection with that key can run exactly
that program's verbs; there is no shell, no pty, no port forwarding. The
device holds only public keys (installed by the `rp5-agents` recipe into the
signed, verity-protected root); the private keys live on the server
(`secure-boot-keys/ssh/`).

| Service | key / user | program | privilege | verbs |
|---|---|---|---|---|
| attestation | `attest` | `rp5-attest` | none (TPM only) | `quote`, `status` |
| OTA | `ota` | `rp5-ota` -> `sudo rp5-ota-priv` | root helper, one sudoers rule | `status`, `install`, `tryboot`, `commit`, `reboot` |
| provisioning | `provision` | `rp5-provision` -> `sudo rp5-provision-priv` | root helper, one sudoers rule | `provision`, `enroll`, `verify` |

Protocol: the verb is what the client asked to run (`ssh ota@board install`),
which dropbear passes as `SSH_ORIGINAL_COMMAND`; the request body is stdin
(JSON, or a tar stream for `install`); the reply is one JSON line on stdout
(`{"ok": true, ...}` or `{"ok": false, "error": ...}`). The privileged halves
take their verb from argv only and re-check everything.

None of the programs reads a secret: the DUID is not in the devicetree, the
measured-boot index is read with the empty platform auth, the anti-rollback
counter is advanced by U-Boot only, and provisioning receives auth values
that the factory host derived (it never sees the DUID or the master secret).

## OTA rules enforced on the device

- The target pair is the one `autoboot.txt` names in `[tryboot]`, and it must
  differ from the pair the firmware booted from (never write the running
  release). Both halves check; the file must be a valid A/B file.
- Every write is read back and compared with the manifest digest (root slot
  raw, boot files on FAT).
- A release whose version is below the anti-rollback counter is refused
  before anything is written (U-Boot would refuse it at boot anyway).
- `commit` only on a trial boot (firmware `tryboot` = 1) and only when the
  running pair is the one `[tryboot]` names; it is the single rewrite of
  `autoboot.txt` (temp file, sync, rename, sync). The counter is never touched
  by the agent: U-Boot advances it on the first committed boot.

## Server side

```
agents/server/rp5.py status | attest | install <dir> | tryboot | commit | reboot
agents/server/rp5.py update <release-dir>     # the whole cycle, attestation = health check
agents/server/rp5.py provision <auths.json> | enroll | verify
agents/server/make-release.py --version N --out <dir> --bootfs <template>
```

`BOARD`, `KEYS`, `REBOOT_WAIT` in the environment. `attest` runs
`attestation/attest-server.py` with `AGENT=1` (the JSON protocol; the legacy
script + scp path is kept for releases before r6).

A release directory: `MANIFEST.json` (version, digests, cmdline template,
goldens the host can compute), `boot.img`, `boot.sig`, `rootfs.img`.
