FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " file://tpm.cfg"
KERNEL_CONFIG_FRAGMENTS:append = " ${WORKDIR}/tpm.cfg"

