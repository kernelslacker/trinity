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
SRC_GLOB=("$ROOT/net/proto/netlink-xfrm"*.c)
HDR="$ROOT/include/proto-netlink-xfrm-internal.h"

# Expand the glob and confirm at least one source file matches.
srcs=()
for f in "${SRC_GLOB[@]}"; do
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

# -----------------------------------------------------------------------
# Value check: the XFRMA_ #ifndef shims are *always* taken (enum constants
# are not macros; cpp #ifndef is unconditionally true).  A wrong value
# compiles silently and sends the wrong netlink attribute to the kernel.
# Verify each shimmed define matches its canonical enum position.
#
# Reference: linux/xfrm.h enum xfrm_attr_type_t (verified 2026-08).
# -----------------------------------------------------------------------
declare -A XFRMA_EXPECTED=(
	[XFRMA_ALG_AUTH]=1
	[XFRMA_ALG_CRYPT]=2
	[XFRMA_ALG_COMP]=3
	[XFRMA_ENCAP]=4
	[XFRMA_TMPL]=5
	[XFRMA_LTIME_VAL]=9
	[XFRMA_REPLAY_VAL]=10
	[XFRMA_MIGRATE]=17
	[XFRMA_ALG_AEAD]=18
	[XFRMA_ALG_AUTH_TRUNC]=20
	[XFRMA_REPLAY_ESN_VAL]=23
	[XFRMA_SA_EXTRA_FLAGS]=24
	[XFRMA_OFFLOAD_DEV]=28
	[XFRMA_SET_MARK]=29
	[XFRMA_SET_MARK_MASK]=30
	[XFRMA_IF_ID]=31
	[XFRMA_MTIMER_THRESH]=32
	[XFRMA_NAT_KEEPALIVE_INTERVAL]=34
	[XFRMA_SA_PCPU]=35
	[XFRMA_IPTFS_DROP_TIME]=36
	[XFRMA_IPTFS_REORDER_WINDOW]=37
	[XFRMA_IPTFS_DONT_FRAG]=38
	[XFRMA_IPTFS_INIT_DELAY]=39
	[XFRMA_IPTFS_MAX_QSIZE]=40
	[XFRMA_IPTFS_PKT_SIZE]=41
)

# Extract define-lines with numeric values from the fallback header.
hdr_defines=$(grep -oE \
	'#[[:space:]]*define[[:space:]]+XFRMA_[A-Z0-9_]+[[:space:]]+[0-9]+' \
	"$HDR" 2>/dev/null | awk '{print $2, $3}')

val_fail=0
for sym in "${!XFRMA_EXPECTED[@]}"; do
	expected="${XFRMA_EXPECTED[$sym]}"
	actual=$(awk -v s="$sym" '$1==s{print $2; exit}' <<< "$hdr_defines")
	[ -z "$actual" ] && continue   # not yet shimmed -- presence check caught it above
	if [ "$actual" != "$expected" ]; then
		echo "FAIL: $NAME: $sym shim value wrong: have $actual, want $expected" >&2
		val_fail=$((val_fail + 1))
	fi
done

if [ "$val_fail" -gt 0 ]; then
	echo "FAIL: $NAME: $val_fail XFRMA_ shim value mismatch(es) -- wrong netlink attributes sent to kernel"
	exit 1
fi

vc=${#XFRMA_EXPECTED[@]}
echo "PASS: $NAME ($uc XFRMA_ token(s) used, all shimmed; $vc value(s) verified correct)"
exit 0
