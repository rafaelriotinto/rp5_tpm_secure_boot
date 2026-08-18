FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Replace the default U-Boot source with the project's fork of
# xen-troops/u-boot (adds RP1 PCIe/GPIO/clock drivers for RPi5 and the
# TPM measured-boot work developed in this project).
SRC_URI = "git://github.com/rafaelriotinto/u-boot.git;protocol=https;branch=rpi5-tpm-measured-boot \
           file://uboot-tpm.cfg \
           "

# Pinned for reproducibility. Update when the branch advances.
SRCREV = "12329778850d2cd2a76957ca000479fdfac55297"

S = "${WORKDIR}/git"

# Override version to reflect the xen-troops base branch (2024.04)
PV = "2024.04+git${SRCPV}"

# For local U-Boot development it is faster to build from a local checkout
# than to push/fetch through the repository. Override in build/conf/local.conf
# (site-specific, not part of this layer):
#   INHERIT += "externalsrc"
#   EXTERNALSRC:pn-u-boot = "/LINUX_YOCTO_RP5_TPM_ENV/u-boot"

# Merge the TPM config fragment into .config
do_configure:append() {
    if [ -f ${WORKDIR}/uboot-tpm.cfg ]; then
        cat ${WORKDIR}/uboot-tpm.cfg >> ${B}/.config
        oe_runmake -C ${S} O=${B} oldconfig
    fi
}
