FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " file://tpm.cfg file://dm-verity.cfg file://lockdown.cfg"
KERNEL_CONFIG_FRAGMENTS:append = " ${WORKDIR}/tpm.cfg ${WORKDIR}/dm-verity.cfg ${WORKDIR}/lockdown.cfg"

