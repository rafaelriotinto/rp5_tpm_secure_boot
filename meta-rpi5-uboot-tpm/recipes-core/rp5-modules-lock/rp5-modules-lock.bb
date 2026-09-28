SUMMARY = "Disable kernel module loading after the boot-time drivers are loaded"
DESCRIPTION = "A one-shot unit that sets kernel.modules_disabled=1 before any \
network-facing service starts, so that no kernel code can be loaded after boot."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://rp5-modules-lock.service"
S = "${WORKDIR}"

inherit systemd
SYSTEMD_SERVICE:${PN} = "rp5-modules-lock.service"
SYSTEMD_AUTO_ENABLE = "enable"

do_install() {
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${WORKDIR}/rp5-modules-lock.service ${D}${systemd_system_unitdir}/
}
