SUMMARY = "The three device services: attestation, OTA update, provisioning"
DESCRIPTION = "Small Python programs run as forced commands behind dropbear: each \
service is one SSH key bound to one user and one program (command= in \
authorized_keys), so a connection can do exactly that service's verbs and never \
gets a shell. Attestation runs unprivileged as 'attest'. OTA and provisioning have \
an unprivileged network-facing half ('ota', 'provision') that hands over to a root \
helper through a single sudoers rule each. Sources live in <repo>/agents/ so there \
is exactly one copy."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

FILESEXTRAPATHS:prepend := "${THISDIR}/../../../agents:"
SRC_URI = "file://rp5agent/__init__.py \
           file://rp5-attest file://rp5-ota file://rp5-ota-priv \
           file://rp5-provision file://rp5-provision-priv \
           file://authorized_keys.attest file://authorized_keys.ota \
           file://authorized_keys.provision file://sudoers-rp5-agents"
S = "${WORKDIR}"

inherit useradd
USERADD_DEPENDS = "tpm2-tss attest-user"
USERADD_PACKAGES = "${PN}"
USERADD_PARAM:${PN} = "--system --home-dir /home/ota --no-create-home --shell /bin/sh --groups tss --user-group ota; \
                       --system --home-dir /home/provision --no-create-home --shell /bin/sh --groups tss --user-group provision"

RDEPENDS:${PN} = "python3-core python3-json python3-compression python3-crypt python3-io python3-shell python3-netclient python3-misc tpm2-tools sudo attest-user"

do_install() {
    install -d ${D}${libdir}/rp5agent
    install -m 0644 ${WORKDIR}/rp5agent/__init__.py ${D}${libdir}/rp5agent/
    install -d ${D}${bindir}
    for f in rp5-attest rp5-ota rp5-ota-priv rp5-provision rp5-provision-priv; do
        install -m 0755 ${WORKDIR}/$f ${D}${bindir}/$f
    done
    # forced-command keys: the device holds only public keys
    for u in ota provision; do
        install -d -m 0700 ${D}/home/$u/.ssh
        install -m 0600 ${WORKDIR}/authorized_keys.$u ${D}/home/$u/.ssh/authorized_keys
        chown -R $u:$u ${D}/home/$u
    done
    install -d -m 0700 ${D}/home/attest/.ssh
    install -m 0600 ${WORKDIR}/authorized_keys.attest ${D}/home/attest/.ssh/authorized_keys
    chown -R attest:attest ${D}/home/attest
    install -d -m 0750 ${D}${sysconfdir}/sudoers.d
    install -m 0440 ${WORKDIR}/sudoers-rp5-agents ${D}${sysconfdir}/sudoers.d/rp5-agents
    # state for the OTA service (staged releases); /data is mounted noexec
    install -d ${D}${sysconfdir}/tmpfiles.d
    echo "d /data/ota 0700 ota ota -" > ${D}${sysconfdir}/tmpfiles.d/rp5-ota.conf
}

FILES:${PN} = "${bindir} ${libdir}/rp5agent /home/ota /home/provision /home/attest/.ssh ${sysconfdir}/sudoers.d ${sysconfdir}/tmpfiles.d"
# attest-user installs an unrestricted key for attest; this recipe replaces it
RCONFLICTS:${PN} = ""
