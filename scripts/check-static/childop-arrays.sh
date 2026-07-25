#!/bin/bash
#
# childop-arrays: verify that childop-indexed dispatch tables and switch
# statements have one entry per `enum child_op_type` value.
#
# Trinity dispatches per-child work via several parallel structures
# keyed by `enum child_op_type` (see include/child-api.h).  With the
# X-macro registry in include/childop.def, alt_op_name() and any other
# per-op switch are generated from the same row set as op_dispatch[],
# so a missing case is now a compile error.  What can still drift is
# the enum itself: if someone edits enum child_op_type directly (or
# edits childop.def without touching the enum in the pre-X-macro
# transition period), the row count and the enum value count diverge.
#
# What this check enforces today:
#   1. op_dispatch[] in child/child-altop-table.c has exactly one
#      designated initializer per CHILD_OP_* enum value.
#   2. childop.def has exactly one CHILDOP() row per CHILD_OP_* enum
#      value.

set -u

NAME="childop-arrays"
ROOT="${REPO_ROOT:-$(pwd)}"

CHILD_H="$ROOT/include/child-api.h"
CHILD_C="$ROOT/child/child-altop-table.c"
CHILD_DEF="$ROOT/include/childop.def"

fail() {
	echo "FAIL: $NAME: $1"
	shift
	for line in "$@"; do
		echo "  $line" >&2
	done
	exit 1
}

[ -r "$CHILD_H" ] || fail "cannot read $CHILD_H"
[ -r "$CHILD_C" ] || fail "cannot read $CHILD_C"
[ -r "$CHILD_DEF" ] || fail "cannot read $CHILD_DEF"

# Extract CHILD_OP_* enum values inside `enum child_op_type { ... }`.
# Exclude NR_CHILD_OP_TYPES (the count sentinel).
enum_count=$(awk '
	/enum child_op_type \{/ { inside = 1; next }
	inside && /^\}/         { inside = 0 }
	inside && /^\s*CHILD_OP_[A-Z0-9_]+\s*[=,]/ { print }
' "$CHILD_H" | wc -l)

if [ "$enum_count" -eq 0 ]; then
	fail "found 0 CHILD_OP_* values in $CHILD_H (parser broke?)"
fi

# Count designated initializers in op_dispatch[].
dispatch_count=$(awk '
	/bool .*op_dispatch\[NR_CHILD_OP_TYPES\].*= \{/ { inside = 1; next }
	inside && /^\};/         { inside = 0 }
	inside && /^\s*\[CHILD_OP_[A-Z0-9_]+\]\s*=/ { print }
' "$CHILD_C" | wc -l)

if [ "$dispatch_count" -ne "$enum_count" ]; then
	fail "op_dispatch[] has $dispatch_count entries but enum has $enum_count values" \
		"see child/child-altop-table.c op_dispatch[] and include/child-api.h enum child_op_type"
fi

# Count CHILDOP() rows in childop.def.
def_count=$(awk '/^CHILDOP\(CHILD_OP_[A-Z0-9_]+/ { print }' "$CHILD_DEF" | wc -l)

if [ "$def_count" -ne "$enum_count" ]; then
	fail "childop.def has $def_count CHILDOP() rows but enum has $enum_count values" \
		"see include/childop.def and include/child-api.h enum child_op_type"
fi

echo "PASS: $NAME (enum=$enum_count, op_dispatch=$dispatch_count, childop_def=$def_count)"
exit 0
