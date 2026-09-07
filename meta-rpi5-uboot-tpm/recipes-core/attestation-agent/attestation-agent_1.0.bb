SUMMARY = "Device side of remote attestation (attest-device.sh)"
DESCRIPTION = "Installs the attestation agent into the measured, verity-protected root \
filesystem. It holds no secret: an AK-signed quote of PCRs 0/1/8/9 and an NV_Certify \
of the measured-boot index read with empty platform auth. Board binding is by attested \
reboot (the server checks the TPM resetCount and the NV commitment). Run as the \
non-root 'attest' user. The source of truth is attestation/attest-device.sh in the \
repository root; this recipe takes it from there rather than keeping a copy."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

# The layer lives inside the rp5_tpm_secure_boot repo; reach the script in
# <repo>/attestation/ so there is exactly one copy of it.
FILESEXTRAPATHS:prepend := "${THISDIR}/../../../attestation:"
SRC_URI = "file://attest-device.sh"
S = "${WORKDIR}"

RDEPENDS:${PN} = "tpm2-tools attest-user"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${WORKDIR}/attest-device.sh ${D}${bindir}/attest-device.sh
}
