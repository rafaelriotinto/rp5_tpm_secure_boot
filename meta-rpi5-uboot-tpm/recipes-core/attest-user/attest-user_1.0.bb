SUMMARY = "Dedicated non-root user for remote attestation, plus SSH public keys"
DESCRIPTION = "Creates the 'attest' user (member of group tss only, so it can use \
/dev/tpmrm0 and nothing else; locked password; login by SSH key only) and installs \
the attestation server's PUBLIC key for 'attest' and for root. The device holds \
only public keys: on each connection it challenges the client to prove possession \
of the matching private key, which never leaves the attestation server. \
Installing root's key now is what makes removing debug-tweaks (empty root password) \
later a safe, one-line change."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://authorized_keys"
S = "${WORKDIR}"

inherit useradd

# The tss group is created by tpm2-tss's own useradd. USERADD_DEPENDS pulls
# that recipe's users/groups into THIS recipe's sysroot, so "--groups tss"
# resolves at build time; RDEPENDS keeps the install order right on the rootfs.
USERADD_DEPENDS = "tpm2-tss"
RDEPENDS:${PN} = "tpm2-tss"

USERADD_PACKAGES = "${PN}"
USERADD_PARAM:${PN} = "--system --home-dir /home/attest --no-create-home \
                       --shell /bin/sh --groups tss --user-group attest"

do_install() {
    install -d -m 0700 ${D}/home/attest/.ssh
    install -m 0600 ${WORKDIR}/authorized_keys ${D}/home/attest/.ssh/authorized_keys
    chown -R attest:attest ${D}/home/attest

    install -d -m 0700 ${D}/root/.ssh
    install -m 0600 ${WORKDIR}/authorized_keys ${D}/root/.ssh/authorized_keys
}

# The password is locked at rootfs assembly (extrausers in the image recipe),
# because usermod runs against the finished rootfs, not this package.
FILES:${PN} = "/home/attest /root/.ssh"
