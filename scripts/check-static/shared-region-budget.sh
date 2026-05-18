#!/bin/bash
#
# shared-region-budget: tripwire that warns when the number of
# shared-region producer call sites approaches MAX_SHARED_ALLOCS.
#
# shared_regions[] in utils.c is a fixed-size table (MAX_SHARED_ALLOCS,
# see include/utils.h) that backs the range_overlaps_shared() guards
# in the mm-syscall sanitisers.  When the table overflows the silent
# failure mode is: extra regions are NOT tracked and the fuzzer
# happily munmaps/mremaps/madvises them.  Silent under-protection IS
# the bug class.
#
# Each call site of alloc_shared() / track_shared_region() registers
# one region per execution.  Many sites are inside loops or are called
# once at init, so call-site count is an upper bound, not a true total.
# That is still the right tripwire: if call-site count crosses some
# fraction of MAX_SHARED_ALLOCS we should look at the table sizing
# before the next batch of shared-region producers lands.
#
# Threshold: 50% of MAX_SHARED_ALLOCS.  This is conservative on
# purpose -- the cost of a false alarm is "go look at utils.h", the
# cost of a missed warning is silent fuzzer corruption on the
# isolated host.

set -u

NAME="shared-region-budget"
ROOT="${REPO_ROOT:-$(pwd)}"

UTILS_H="$ROOT/include/utils.h"
[ -r "$UTILS_H" ] || { echo "FAIL: $NAME: cannot read $UTILS_H"; exit 1; }

MAX=$(awk '/^#define[[:space:]]+MAX_SHARED_ALLOCS[[:space:]]+[0-9]+/ { print $3; exit }' "$UTILS_H")
if [ -z "$MAX" ] || [ "$MAX" -le 0 ]; then
	echo "FAIL: $NAME: could not parse MAX_SHARED_ALLOCS from $UTILS_H"
	exit 1
fi

# Count distinct call sites of the two producer functions across the
# tree (excluding utils.c where the functions are defined and the
# bookkeeping happens, and headers where declarations live).
sites=$(grep -rEn '\b(alloc_shared|track_shared_region)[[:space:]]*\(' "$ROOT" \
	--include='*.c' --include='*.h' 2>/dev/null \
	| grep -v ':utils\.c:' \
	| grep -v '/utils\.c:' \
	| grep -v '/include/' \
	| grep -vE '^[^:]+:[0-9]+:[[:space:]]*(\*|/\*|//)' \
	| wc -l)

half=$((MAX / 2))

if [ "$sites" -ge "$half" ]; then
	echo "WARN: $NAME: $sites call site(s), >= 50% of MAX_SHARED_ALLOCS=$MAX -- raise MAX_SHARED_ALLOCS or move shared_regions[] to dynamic resize"
	exit 0
fi

pct=$(( sites * 100 / MAX ))
echo "PASS: $NAME ($sites call sites, MAX_SHARED_ALLOCS=$MAX, $pct% of budget)"
exit 0
