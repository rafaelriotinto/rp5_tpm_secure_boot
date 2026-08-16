SUMMARY = "DT overlay for Letstrust TPM"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://letstrust-tpm-overlay.dts"

# We need the device tree compiler
DEPENDS = "dtc-native"

inherit deploy

do_compile() {
    # Compile the dts to dtbo
    dtc -@ -I dts -O dtb -o ${WORKDIR}/letstrust-tpm.dtbo ${WORKDIR}/letstrust-tpm-overlay.dts
}

do_deploy() {
    # Install directly into the overlays folder in the deploy area
    install -d ${DEPLOYDIR}/overlays
    install -m 0644 ${WORKDIR}/letstrust-tpm.dtbo ${DEPLOYDIR}/overlays/letstrust-tpm.dtbo
}

# Ensure the deploy task runs
addtask deploy after do_compile before do_build