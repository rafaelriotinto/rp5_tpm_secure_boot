SUMMARY = "Set default TPM2TOOLS_TCTI for tpm2-tools"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COREBASE}/meta/files/common-licenses/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://tpm2-tools.sh"
S = "${WORKDIR}"

do_install() {
    install -d ${D}${sysconfdir}/profile.d
    install -m 0644 ${WORKDIR}/tpm2-tools.sh ${D}${sysconfdir}/profile.d/tpm2-tools.sh
}