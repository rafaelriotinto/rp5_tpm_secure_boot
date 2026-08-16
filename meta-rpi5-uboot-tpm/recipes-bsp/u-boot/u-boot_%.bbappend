FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# # REPLACE the default U-Boot source with xen-troops
# SRC_URI = "git://github.com/xen-troops/u-boot.git;protocol=https;branch=rpi5-2024.04-xt"

# # Pin specific commit for reproducibility
# SRCREV = "${AUTOREV}"

inherit externalsrc
EXTERNALSRC:pn-u-boot = "/LINUX_DOCKER_SHARE/xen-troops-uboot/u-boot"
# EXTERNALSRC_BUILD:pn-u-boot = "/LINUX_DOCKER_SHARE/xen-troops-uboot/u-boot"

# Add TPM config fragment
SRC_URI += "file://uboot-tpm.cfg"

# Set source directory
S = "${WORKDIR}/git"

# Override version to reflect the xen-troops branch
PV = "2024.04+git${SRCPV}"

# Merge the config fragment into .config
do_configure:append() {
    if [ -f ${WORKDIR}/uboot-tpm.cfg ]; then
        cat ${WORKDIR}/uboot-tpm.cfg >> ${B}/.config
        oe_runmake -C ${S} O=${B} oldconfig
    fi
}