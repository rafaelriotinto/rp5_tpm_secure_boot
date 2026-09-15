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
	echo "p$p: $(mcopy -i "$WIC@@$OFF" ::boot.img - | sha256sum | cut -c1-16)"
done
echo "release: $(sha256sum "$REL/boot.img" | cut -c1-16)"
