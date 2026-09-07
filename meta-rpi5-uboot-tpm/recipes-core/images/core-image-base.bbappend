# Hardened root filesystem for the raspberrypi5-uboot-tpm machine.
#
#  - read-only root, integrity-protected by dm-verity. The hash tree is
#    appended to the ext4 image (single-partition layout); the ROOT HASH goes
#    into the kernel command line inside the signed boot.img
#    (dm-mod.create=... root=/dev/dm-0), so it is signed by the owner key AND
#    measured into PCR 1 by U-Boot -- the rootfs joins the measured boot
#    record by construction, with no initramfs.
#  - a separate writable data partition (/data, noexec,nosuid,nodev) for
#    mutable state only. Anything on it is untrusted input.
#  - a dedicated non-root 'attest' user (group tss only), SSH keys installed
#    for it and for root. debug-tweaks is still present at this stage (empty
#    root password); it is removed, together with locking root and masking the
#    gettys, once the verity boot path is proven.

IMAGE_FEATURES += "read-only-rootfs"

# dm-verity-img (meta-security): produces <image>.ext4.verity + .verity.env
DM_VERITY_IMAGE = "core-image-base"
DM_VERITY_IMAGE_TYPE = "ext4"
DM_VERITY_SEPARATE_HASH = "0"
# ext4 blocks, verity data blocks and verity hash blocks are ALL 4 KiB. They
# must agree: dm-verity exports its data block size as the device's logical
# block size, and ext4 refuses a filesystem whose block size is smaller than
# that ("bad block size 1024" -- mke2fs picks 1 KiB blocks for small images).
EXTRA_IMAGECMD:ext4 = "-i 4096 -b 4096"
DM_VERITY_IMAGE_DATA_BLOCK_SIZE = "4096"
IMAGE_CLASSES += "dm-verity-img"
IMAGE_FSTYPES:append = " ext4"

IMAGE_INSTALL:append = " cryptsetup attest-user rp5-data-partition attestation-agent"

# Lock the attest user's password: login by SSH key only. (root is left as
# debug-tweaks sets it, for now.)
inherit extrausers
EXTRA_USERS_PARAMS = "usermod -L attest;"

# /data: the writable, no-exec partition. LABEL= is resolved by
# systemd-fstab-generator via udev's /dev/disk/by-label.
rp5_add_data_fstab() {
    echo "LABEL=data  /data  ext4  defaults,noexec,nosuid,nodev,nofail  0  2" >> ${IMAGE_ROOTFS}${sysconfdir}/fstab
}
ROOTFS_POSTPROCESS_COMMAND += "rp5_add_data_fstab; "
