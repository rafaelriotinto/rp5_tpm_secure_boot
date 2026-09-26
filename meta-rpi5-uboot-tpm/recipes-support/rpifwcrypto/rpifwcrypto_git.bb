SUMMARY = "Raspberry Pi firmware cryptography service client (rpi-fw-crypto)"
DESCRIPTION = "Library and command-line tool for the VideoCore firmware crypto service: \
generate an ECDSA P-256 key in OTP, read its public key, sign digests, and lock key \
operations until reboot. Used by the provisioning service (firmware-key anchor); in \
production U-Boot locks the key before Linux starts."
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://${WORKDIR}/git/LICENCE;md5=4c01239e5c3a3d133858dedacdbca63c"

# raspberrypi/utils master, 2026-06-17 "rpifwcrypto: Fine-grained locking"
SRC_URI = "git://github.com/raspberrypi/utils;protocol=https;branch=master"
SRCREV = "61371fa6d93463c5451131f7bb68ae145aaf1e7a"
PV = "20260617+git"

S = "${WORKDIR}/git/rpifwcrypto"
DEPENDS = "gnutls"
inherit cmake pkgconfig

FILES:${PN} += "${libdir}/librpifwcrypto.so.*"
FILES:${PN}-dev += "${libdir}/librpifwcrypto.so ${includedir}"
