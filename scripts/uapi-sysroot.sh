#!/bin/bash
#
# uapi-sysroot.sh KERNEL_SRC TAG SYSROOT
#
# Build the --sysroot `make uapi-check` compiles against: the uapi
# headers of kernel TAG, installed from the git tree KERNEL_SRC without
# writing to it, with the host's libc headers and libraries alongside.
# A finished SYSROOT is reused until it is deleted.

set -eu

if [ $# -ne 3 ] || [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
	echo "usage: $0 KERNEL_SRC TAG SYSROOT" >&2
	exit 1
fi
KERNEL_SRC="$1"
TAG="$2"
SYSROOT="$3"

[ -e "$SYSROOT/.complete" ] && exit 0
if [ -e "$SYSROOT" ]; then
	echo "uapi-sysroot: $SYSROOT exists but is not a finished sysroot; remove it" >&2
	exit 1
fi

# A hook or a rebase exec exports GIT_DIR and friends, which would point
# git at the repository that ran make instead of KERNEL_SRC.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
	GIT_COMMON_DIR GIT_PREFIX

if ! git -C "$KERNEL_SRC" rev-parse --verify --quiet "$TAG^{commit}" >/dev/null; then
	echo "uapi-sysroot: $KERNEL_SRC has no tag $TAG" >&2
	exit 1
fi

tmp="$SYSROOT.tmp"
rm -rf "$tmp"
mkdir -p "$tmp/src"
trap 'rm -rf "$tmp"' EXIT

# headers_install needs a tree to build its helpers in; an archive of
# the tag gives it one without touching KERNEL_SRC.  Only the installed
# headers are kept.  The kernel's make must not inherit trinity's
# command-line variables or jobserver through MAKEFLAGS.
git -C "$KERNEL_SRC" archive --format=tar "$TAG" | tar -x -C "$tmp/src"
env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL \
	make -s -C "$tmp/src" headers_install INSTALL_HDR_PATH="$tmp/usr"
rm -rf "$tmp/src"

# --sysroot moves the libc headers too, so link the host's in beside the
# kernel's.  Every directory the kernel exports is left out, the ones
# TAG predates included, or a newer host copy would hide what TAG lacks.
inc="$tmp/usr/include"
kdirs=" asm $(ls "$inc") $(git -C "$KERNEL_SRC" ls-tree -d --name-only HEAD include/uapi/ | sed 's|.*/||') "
link_libc_dir() {
	local d
	for d in "$1"/*; do
		case "$kdirs" in *" ${d##*/} "*) continue ;; esac
		[ -e "$2/${d##*/}" ] || ln -s "$d" "$2/${d##*/}"
	done
}
multiarch=$(${CC:-cc} -print-multiarch 2>/dev/null || true)
if [ -n "$multiarch" ] && [ -d "/usr/include/$multiarch" ]; then
	mkdir -p "$inc/$multiarch"
	link_libc_dir "/usr/include/$multiarch" "$inc/$multiarch"
fi
link_libc_dir /usr/include "$inc"

# The libc installs these three into scsi/, which the kernel exports too.
for f in scsi/scsi.h scsi/scsi_ioctl.h scsi/sg.h; do
	if [ -e "/usr/include/$f" ] && [ ! -e "$inc/$f" ]; then
		mkdir -p "$inc/scsi"
		ln -s "/usr/include/$f" "$inc/$f"
	fi
done

# configure links its probes, and the libc's linker scripts name their
# libraries by absolute path, which the linker resolves inside the sysroot.
for d in lib lib64 usr/lib usr/lib64; do
	if [ -d "/$d" ]; then
		ln -s "/$d" "$tmp/$d"
	fi
done

touch "$tmp/.complete"
mv "$tmp" "$SYSROOT"
trap - EXIT
echo "uapi-sysroot: $TAG headers installed in $SYSROOT ($(du -sh "$SYSROOT" | cut -f1), ${SECONDS}s)"
