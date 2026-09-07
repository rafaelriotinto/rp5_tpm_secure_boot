SUMMARY = "Writable, no-exec data partition for a dm-verity read-only root"
DESCRIPTION = "Mounts the 'data' partition at /data with noexec,nosuid,nodev -- \
mutable state only, nothing executable. The root filesystem is integrity- \
protected and read-only; /data is treated as untrusted input. Also points \
dropbear at /data/dropbear so host keys persist across boots."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://dropbear-data.conf file://dropbear-data-server.conf file://dropbear-data.env"
S = "${WORKDIR}"

inherit allarch

do_install() {
    install -d ${D}${sysconfdir}/systemd/system/dropbearkey.service.d
    install -m 0644 ${WORKDIR}/dropbear-data.conf \
        ${D}${sysconfdir}/systemd/system/dropbearkey.service.d/10-data.conf
    install -d ${D}${sysconfdir}/systemd/system/dropbear@.service.d
    install -m 0644 ${WORKDIR}/dropbear-data-server.conf \
        ${D}${sysconfdir}/systemd/system/dropbear@.service.d/10-data.conf
    install -m 0644 ${WORKDIR}/dropbear-data.env ${D}${sysconfdir}/dropbear-data.env
    install -d ${D}/data
}

# The fstab entry for /data is added by the image (rootfs postprocess), since
# /etc/fstab is generated there.
FILES:${PN} = "${sysconfdir}/systemd/system ${sysconfdir}/dropbear-data.env /data"
RDEPENDS:${PN} = "dropbear"
