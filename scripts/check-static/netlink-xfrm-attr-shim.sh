#!/bin/bash
#
# netlink-xfrm-attr-shim: every XFRMA_* token used in the
# net/proto/netlink-xfrm*.c generators must be #define'd in
# include/proto-netlink-xfrm-internal.h.
#
# Why this exists: when the build sysroot's <linux/xfrm.h> is missing or
# older than the newest attribute the generator references, the fallback
# #ifndef block in include/proto-netlink-xfrm-internal.h is what supplies
# the XFRMA_ IDs.  A newly-used attribute that has no fallback still
# compiles wherever <linux/xfrm.h> is new enough, so the gap is invisible
# there -- then the build breaks against an older header with
# "XFRMA_FOO undeclared here (not in a function)".  We must NOT trust the
# local header (that is exactly what hides the bug), so the fallback
# header is the ownership boundary: add a new XFRMA_ use -> add its
# #ifndef fallback.  Either way it is a conscious, reviewable decision
# instead of a late build surprise.

set -u

NAME="netlink-xfrm-attr-shim"
ROOT="${REPO_ROOT:-$(pwd)}"
SRC_GLOB="$ROOT/net/proto/netlink-xfrm"*.c
HDR="$ROOT/include/proto-netlink-xfrm-internal.h"

# Expand the glob and confirm at least one source file matches.
srcs=()
for f in $SRC_GLOB; do
	[ -f "$f" ] && srcs+=("$f")
done
if [ "${#srcs[@]}" -eq 0 ]; then
	echo "PASS: $NAME (no net/proto/netlink-xfrm*.c sources)"
	exit 0
fi
[ -f "$HDR" ] || { echo "PASS: $NAME (no $HDR)"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "WARN: $NAME: perl unavailable, skipping"; exit 0; }

# XFRMA_ tokens used in code (strip C comments so a token named only in a
# comment does not count as a use).
used=$(perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "${srcs[@]}" 2>/dev/null \
	| grep -oE '\bXFRMA_[A-Z0-9_]+\b' | sort -u)

# XFRMA_ tokens trinity #defines in the fallback header (header-independent).
defined=$(grep -hoE '#[[:space:]]*define[[:space:]]+XFRMA_[A-Z0-9_]+' \
	"$HDR" 2>/dev/null | awk '{print $NF}' | sort -u)

missing=$(comm -23 <(printf '%s\n' "$used") <(printf '%s\n' "$defined"))

if [ -n "$missing" ]; then
	echo "FAIL: $NAME: XFRMA_ token(s) used in net/proto/netlink-xfrm*.c with no fallback definition:" >&2
	printf '%s\n' "$missing" | sed 's/^/    /' >&2
	echo "  Fix: extend the XFRMA_ #ifndef fallback block in" >&2
	echo "  include/proto-netlink-xfrm-internal.h so the build works when" >&2
	echo "  <linux/xfrm.h> is absent or predates the attribute." >&2
	n=$(printf '%s\n' "$missing" | grep -c .)
	echo "FAIL: $NAME: $n unshimmed XFRMA_ token(s)"
	exit 1
fi

uc=$(printf '%s\n' "$used" | grep -c .)
echo "PASS: $NAME ($uc XFRMA_ token(s) used, all shimmed in $(basename "$HDR"))"
exit 0
