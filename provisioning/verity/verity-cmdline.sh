#!/bin/bash
# verity-cmdline.sh -- derive the kernel command-line fragment that mounts a
# dm-verity root WITHOUT an initramfs (CONFIG_DM_INIT), and PROVE it correct.
#
# Input:  the <image>.ext4.verity file and its .verity.env, both produced by
#         meta-security's dm-verity-img class.
# Output: the exact string to put in cmdline.txt (inside the signed boot.img):
#
#   dm-mod.create="vroot,,,ro,0 <sectors> verity 1 <dev> <dev> <dbs> <hbs> \
#                  <data_blocks> <hash_start> <alg> <root_hash> <salt>" \
#   root=/dev/dm-0 ro
#
# Why prove it: one number in that table, hash_start, is NOT in the .env. With
# veritysetup's default layout a superblock occupies the first hash block, so
# hash_start = hash_offset / hash_block_size + 1. Off by one => the kernel
# cannot open the root => the board does not boot, and there is no console.
# So this script (1) computes it, (2) asks the HOST kernel to open the very same
# image with veritysetup, (3) reads back the table the kernel accepted, and
# (4) refuses to print anything unless the two agree.
#
# Needs root on the host (loop device + device-mapper).
#
# Usage: sudo ./verity-cmdline.sh <image.ext4.verity> <image.ext4.verity.env> [<board-dev>]
#        board-dev defaults to /dev/mmcblk0p3
set -euo pipefail

IMG="${1:?image.ext4.verity}"; ENVF="${2:?image.ext4.verity.env}"; DEV="${3:-/dev/mmcblk0p3}"
[ "$(id -u)" = 0 ] || { echo "run with sudo (loop + dm)" >&2; exit 2; }

# shellcheck disable=SC1090
. "$ENVF"
: "${ROOT_HASH:?}" "${SALT:?}" "${DATA_BLOCKS:?}" "${DATA_BLOCK_SIZE:?}" "${HASH_BLOCK_SIZE:?}" "${HASH_ALGORITHM:?}" "${DATA_SIZE:?}"

# ---- (1) arithmetic --------------------------------------------------------
HASH_OFFSET=$DATA_SIZE                         # class: hash tree appended at padded data size
HASH_START=$(( HASH_OFFSET / HASH_BLOCK_SIZE + 1 ))   # +1: skip the veritysetup superblock
SECTORS=$(( DATA_BLOCKS * DATA_BLOCK_SIZE / 512 ))

echo "env:  data_blocks=$DATA_BLOCKS dbs=$DATA_BLOCK_SIZE hbs=$HASH_BLOCK_SIZE alg=$HASH_ALGORITHM"
echo "calc: hash_offset=$HASH_OFFSET hash_start=$HASH_START sectors=$SECTORS"
echo "      root_hash=$ROOT_HASH"

# ---- (2)+(3) let the host kernel open it and tell us the table it accepted ----
LOOP=$(losetup --find --show --read-only "$IMG")
NAME="vcheck-$$"
cleanup(){ dmsetup remove "$NAME" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true; }
trap cleanup EXIT

veritysetup open "$LOOP" "$NAME" "$LOOP" "$ROOT_HASH" --hash-offset="$HASH_OFFSET" >/dev/null
TABLE=$(dmsetup table "$NAME")
echo "kernel accepted table:"
echo "      $TABLE"

# table: <start> <len> verity <ver> <ddev> <hdev> <dbs> <hbs> <nblocks> <hash_start> <alg> <hash> <salt> [...]
read -r T_START T_LEN T_TGT T_VER T_DDEV T_HDEV T_DBS T_HBS T_NBLK T_HSTART T_ALG T_HASH T_SALT _ <<<"$TABLE"

# ---- (4) agree, or say nothing -------------------------------------------
ok=1
[ "$T_TGT" = verity ]            || { echo "!! not a verity table" >&2; ok=0; }
[ "$T_LEN" = "$SECTORS" ]        || { echo "!! sectors: calc $SECTORS vs kernel $T_LEN" >&2; ok=0; }
[ "$T_NBLK" = "$DATA_BLOCKS" ]   || { echo "!! data blocks: env $DATA_BLOCKS vs kernel $T_NBLK" >&2; ok=0; }
[ "$T_HSTART" = "$HASH_START" ]  || { echo "!! hash_start: calc $HASH_START vs kernel $T_HSTART" >&2; ok=0; }
[ "$T_HASH" = "$ROOT_HASH" ]     || { echo "!! root hash mismatch" >&2; ok=0; }
[ "$T_SALT" = "$SALT" ]          || { echo "!! salt mismatch" >&2; ok=0; }
[ "$T_ALG" = "$HASH_ALGORITHM" ] || { echo "!! algorithm mismatch" >&2; ok=0; }

# The verity device must also actually READ cleanly end to end (hash tree valid).
if ! dd if="/dev/mapper/$NAME" of=/dev/null bs=1M status=none; then
    echo "!! verity device failed to read: corrupt hash tree or wrong parameters" >&2; ok=0
fi

[ $ok = 1 ] || { echo "REFUSING to emit a cmdline." >&2; exit 1; }

echo
echo "verified: arithmetic == kernel table, and the whole device reads clean."
echo
echo "cmdline fragment (device: $DEV):"
echo "dm-mod.create=\"vroot,,,ro,0 $SECTORS verity 1 $DEV $DEV $DATA_BLOCK_SIZE $HASH_BLOCK_SIZE $DATA_BLOCKS $HASH_START $HASH_ALGORITHM $ROOT_HASH $SALT\" root=/dev/dm-0 ro"
