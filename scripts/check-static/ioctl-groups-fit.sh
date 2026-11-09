#!/bin/bash
#
# ioctl-groups-fit: every ioctl group the tree registers fits the table
# register_ioctl_group() (ioctls/ioctls.c) files them in.
#
# Each REG_IOCTL_GROUP() is a constructor that hands its group to
# register_ioctl_group(), whose table holds IOCTL_GROUPS_MAX
# (include/ioctls.h).  A group past the last slot is dropped at start-up
# with one stderr line, and its requests are never issued.  The count is
# of the REG_IOCTL_GROUP() lines in the comment-stripped sources, which
# takes in a group its file compiles out as well, so it is an upper
# bound: the gate fails before the slots run out on any configuration.
#
# Sources are only read.

set -u

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NAME="ioctl-groups-fit"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

cd "$ROOT" || fail "cannot cd to $ROOT"

max=$(sed -n 's/^#define[[:space:]]\{1,\}IOCTL_GROUPS_MAX[[:space:]]\{1,\}\([0-9]\{1,\}\).*/\1/p' \
	include/ioctls.h)
[ -n "$max" ] || fail "cannot read IOCTL_GROUPS_MAX from include/ioctls.h"

sources="$(list_c_sources)" || fail "cannot list the sources"

count=0
while IFS= read -r f; do
	case "$f" in
	include/ioctls.h|tests/*)
		continue
		;;
	esac
	n=$(strip_c_comments "$f" |
		grep -cE '^[[:space:]]*REG_IOCTL_GROUP[[:space:]]*\(')
	count=$((count + n))
done < <(printf '%s\n' "$sources" | xargs grep -lE 'REG_IOCTL_GROUP' --)

[ "$count" -gt 0 ] ||
	fail "found no REG_IOCTL_GROUP() line, so the scan is broken"
[ "$count" -le "$max" ] ||
	fail "$count ioctl groups are registered and IOCTL_GROUPS_MAX is $max: grow it"

echo "PASS: $NAME: $count of $max ioctl group slots"
