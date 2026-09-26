#!/bin/sh
# inject-boot.sh <card.wic> <release-dir>
# Put a release's signed boot.img + boot.sig into BOTH boot partitions of a card
# image, without mounting anything (mtools on the partition offsets). The Yocto
# build fills the boot partitions with the raw firmware files; under secure boot
# only the signed boot.img is used, and the build cannot sign.
set -e
WIC="${1:?card.wic}"; REL="${2:?release dir}"
for p in 1 2; do
	OFF=$(sfdisk -d "$WIC" | awk -v n="$p" '$1 ~ "wic"n"$" { sub(/,/, "", $4); print $4 * 512 }')
	[ -n "$OFF" ] || { echo "partition $p not found in $WIC" >&2; exit 1; }
	mcopy -o -i "$WIC@@$OFF" "$REL/boot.img" ::boot.img
	mcopy -o -i "$WIC@@$OFF" "$REL/boot.sig" ::boot.sig
	# boot_ramdisk=1: a board WITHOUT the key hash programmed boots the loose partition files
	# unless told to use boot.img; under secure boot the firmware uses boot.img regardless.
	if ! mtype -i "$WIC@@$OFF" ::config.txt | grep -q "^boot_ramdisk=1"; then
		{ mtype -i "$WIC@@$OFF" ::config.txt; printf '\n[all]\nboot_ramdisk=1\n'; } > "${TMPDIR:-/tmp}/cfg.$$"
		mcopy -o -i "$WIC@@$OFF" "${TMPDIR:-/tmp}/cfg.$$" ::config.txt; rm -f "${TMPDIR:-/tmp}/cfg.$$"
	fi
	echo "p$p: $(mcopy -i "$WIC@@$OFF" ::boot.img - | sha256sum | cut -c1-16)"
done
echo "release: $(sha256sum "$REL/boot.img" | cut -c1-16)"
