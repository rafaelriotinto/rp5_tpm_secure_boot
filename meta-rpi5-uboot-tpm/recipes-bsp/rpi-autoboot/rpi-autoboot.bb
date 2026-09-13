SUMMARY = "autoboot.txt for the Raspberry Pi A/B boot-partition scheme"
DESCRIPTION = "Deploys autoboot.txt into the boot partition. The firmware reads it \
from the first partition before anything else: [all] names the partition that \
holds the committed boot.img, [tryboot] the one to try ONCE after \
'reboot \"0 tryboot\"'. tryboot_a_b=1 makes the tryboot flag select a partition \
instead of tryboot.txt. Committing an update = rewriting this file to swap the \
two numbers; the file is not signed, but the firmware verifies whichever \
boot.img it ends up loading, so it can only choose between owner-signed images."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://autoboot.txt"
S = "${WORKDIR}"

inherit deploy nopackages

do_deploy() {
    install -m 0644 ${WORKDIR}/autoboot.txt ${DEPLOYDIR}/autoboot.txt
}
addtask deploy after do_install before do_build
