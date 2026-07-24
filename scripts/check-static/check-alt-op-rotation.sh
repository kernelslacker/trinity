#!/bin/bash
#
# check-alt-op-rotation: every CHILD_OP_* referenced from
# pick_op_type_table[] in child/child-altop-pick.c must be either
# reachable via the dedicated alt-op rotation (alt_op_rotation[]) or
# explicitly listed in scripts/check-static/alt-op-rotation.denylist
# with a reason.
#
# Background: alt_op_rotation[] is hand-maintained.  Newer childops
# can land in pick_op_type_table[] (and thus the random picker / canary
# queue) without being added to the rotation, leaving them effectively
# unreachable for dedicated alt-op children.  The denylist is the
# escape hatch: lifecycle / race / heavyweight ops that we deliberately
# do not want in steady rotation get an entry with REASON: ...; ops
# pending review get a TODO: entry and should be migrated into the
# rotation (or promoted to permanent denials) over time.

set -u

NAME="check-alt-op-rotation"
ROOT="${REPO_ROOT:-$(pwd)}"
CHILD_C="$ROOT/child/child-altop-pick.c"
DENYLIST="$ROOT/scripts/check-static/alt-op-rotation.denylist"

if [ ! -r "$CHILD_C" ]; then
	echo "FAIL: $NAME: cannot read $CHILD_C" >&2
	exit 1
fi

# Extract the CHILD_OP_* tokens that appear inside the body of a named
# C-initializer block (between the opening `<name>[...] = {` line and
# the matching `};`).  Restricting extraction to the table braces is
# important: case labels, helper lookups, and case-of-switch usages
# elsewhere in child.c reference the same constants and would otherwise
# pollute the set.
extract_table_ops() {
	local table="$1" src="$2"
	awk -v tbl="$table" '
		# Match "static ... <tbl>[...] = {" or "<tbl>[] = {" on a
		# single line.  Both forms are used in child/child-altop-pick.c.
		$0 ~ ("(^|[[:space:]])" tbl "\\[[^]]*\\][[:space:]]*=[[:space:]]*\\{") {
			in_tbl = 1
			next
		}
		in_tbl && /^\};/ {
			in_tbl = 0
			next
		}
		in_tbl {
			# Skip preprocessor-disabled regions inside the table.
			if ($0 ~ /^[[:space:]]*#[[:space:]]*if[[:space:]]+0/) {
				in_if0 = 1
				next
			}
			if (in_if0 && $0 ~ /^[[:space:]]*#[[:space:]]*endif/) {
				in_if0 = 0
				next
			}
			if (in_if0) next

			# Strip /* ... */ on a single line.  Multiline block
			# comments are rare inside these tables; if encountered,
			# the worst case is a spurious CHILD_OP_* match -- the
			# pick table is the source of truth, so over-counting
			# the denylist side cannot mask a real omission.
			line = $0
			gsub(/\/\*.*\*\//, "", line)
			gsub(/\/\/.*$/, "", line)

			while (match(line, /CHILD_OP_[A-Z0-9_]+/) > 0) {
				tok = substr(line, RSTART, RLENGTH)
				print tok
				line = substr(line, RSTART + RLENGTH)
			}
		}
	' "$src" | sort -u
}

PICK_OPS="$(extract_table_ops pick_op_type_table "$CHILD_C")"
ROT_OPS="$(extract_table_ops alt_op_rotation "$CHILD_C")"

if [ -z "$PICK_OPS" ]; then
	echo "FAIL: $NAME: pick_op_type_table[] body produced no CHILD_OP_* tokens" >&2
	exit 1
fi
if [ -z "$ROT_OPS" ]; then
	echo "FAIL: $NAME: alt_op_rotation[] body produced no CHILD_OP_* tokens" >&2
	exit 1
fi

# Parse the denylist: strip comments and blanks, take first whitespace
# token of each remaining line.
DENY_OPS=""
if [ -r "$DENYLIST" ]; then
	DENY_OPS="$(sed -e 's/#.*$//' -e 's/[[:space:]]\+$//' "$DENYLIST" \
		| awk 'NF { print $1 }' \
		| sort -u)"
fi

# Covered = rotation ∪ denylist
COVERED="$(printf '%s\n%s\n' "$ROT_OPS" "$DENY_OPS" | sort -u)"

# Missing = pick ops not in covered set.
MISSING="$(comm -23 <(printf '%s\n' "$PICK_OPS") <(printf '%s\n' "$COVERED"))"

# Stale denylist = denylist entries that are no longer in the pick
# table (op renamed or removed).  Advisory only.
STALE="$(comm -23 <(printf '%s\n' "$DENY_OPS") <(printf '%s\n' "$PICK_OPS"))"

missing_count=0
if [ -n "$MISSING" ]; then
	missing_count="$(printf '%s\n' "$MISSING" | wc -l)"
	{
		echo "  $missing_count childop(s) in pick_op_type_table[] are neither in alt_op_rotation[] nor in the denylist:"
		printf '%s\n' "$MISSING" | sed 's/^/    /'
		echo "  fix: either add the symbol to alt_op_rotation[] in child/child-altop-pick.c, OR add a line to"
		echo "       scripts/check-static/alt-op-rotation.denylist with a REASON: (permanent) or"
		echo "       TODO: review for rotation candidacy (pending)."
	} >&2
fi

stale_count=0
if [ -n "$STALE" ]; then
	stale_count="$(printf '%s\n' "$STALE" | wc -l)"
	{
		echo "  note: $stale_count denylist entry/entries no longer appear in pick_op_type_table[] (consider pruning):"
		printf '%s\n' "$STALE" | sed 's/^/    /'
	} >&2
fi

if [ "$missing_count" -gt 0 ]; then
	echo "FAIL: $NAME: $missing_count uncovered childop(s)"
	exit 1
fi

pick_count="$(printf '%s\n' "$PICK_OPS" | wc -l)"
rot_count="$(printf '%s\n' "$ROT_OPS" | wc -l)"
deny_count=0
[ -n "$DENY_OPS" ] && deny_count="$(printf '%s\n' "$DENY_OPS" | wc -l)"

echo "PASS: $NAME (pick=$pick_count, rotation=$rot_count, denylist=$deny_count)"
exit 0
