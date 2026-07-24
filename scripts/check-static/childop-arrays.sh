#!/bin/bash
#
# childop-arrays: verify that childop-indexed dispatch tables and switch
# statements have one entry per `enum child_op_type` value.
#
# Trinity dispatches per-child work via several parallel structures
# keyed by `enum child_op_type` (see include/child.h).  An out-of-sync
# table -- a new CHILD_OP_FOO without a corresponding dispatch entry
# or alt_op_name string -- becomes a silent NULL deref or an "unknown"
# log line at runtime.  Since the fuzzer only runs on an isolated host,
# we want that divergence caught at check time instead.
#
# What this check enforces today:
#   1. op_dispatch[] in child/child-altop-table.c has exactly one
#      designated initializer per CHILD_OP_* enum value.
#   2. alt_op_name() in child/child-altop-table.c has exactly one case
#      label per CHILD_OP_* enum value.

set -u

NAME="childop-arrays"
ROOT="${REPO_ROOT:-$(pwd)}"

CHILD_H="$ROOT/include/child-api.h"
CHILD_C="$ROOT/child/child-altop-table.c"

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
		"see child/child-altop-table.c op_dispatch[] and include/child.h enum child_op_type"
fi

# Count case labels in alt_op_name().
altname_count=$(awk '
	/(static[[:space:]]+)?const char \*alt_op_name\(/ { inside = 1; brace = 0; next }
	inside && /\{/  { brace++ }
	inside && /\}/  { brace--; if (brace == 0) inside = 0 }
	inside && /^\s*case CHILD_OP_[A-Z0-9_]+\s*:/ { print }
' "$CHILD_C" | wc -l)

if [ "$altname_count" -ne "$enum_count" ]; then
	fail "alt_op_name() covers $altname_count of $enum_count CHILD_OP_* values" \
		"see child/child-altop-table.c alt_op_name() and include/child.h enum child_op_type"
fi

echo "PASS: $NAME (enum=$enum_count, op_dispatch=$dispatch_count, alt_op_name=$altname_count)"
exit 0
