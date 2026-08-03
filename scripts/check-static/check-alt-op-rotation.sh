#!/bin/bash
#
# check-alt-op-rotation: enforce two bijection directions around
# pick_op_type_table[] in child/child-altop-pick.c.
#
#   1. Coverage (picker -> rotation): every CHILD_OP_* referenced from
#      pick_op_type_table[] must be either reachable via the dedicated
#      alt-op rotation (alt_op_rotation[]) or explicitly listed in
#      scripts/check-static/alt-op-rotation.denylist with a reason.
#
#   2. Completeness (def -> picker): every CHILDOP(CHILD_OP_*, ...) row
#      in include/childop.def must appear in pick_op_type_table[] OR
#      be explicitly listed in the denylist with an
#      `OMIT-FROM-PICKER: <reason>` tag.  childop.def is the
#      authoritative registry; a silent omission from the picker
#      defaults the slot to CHILD_OP_SYSCALL (designated-initializer
#      zero fill) and is undetectable at runtime.
#
#   3. Uniqueness: no CHILD_OP_* may appear more than once in
#      pick_op_type_table[].  A duplicate silently displaces another
#      op (the second designator overwrites the first slot's value if
#      re-assigned, or the duplicate lands on a slot that would
#      otherwise have held a different op) -- a silent bug.
#
# Background: alt_op_rotation[] is hand-maintained; pick_op_type_table[]
# is generated at compile time out of include/childop.def by an X-macro
# expansion in child/child-altop-pick.c, so the picker slot table is
# always identical to the def-file rows (minus the CHILD_OP_SYSCALL
# sentinel).  Direction 2 (def -> picker) is therefore trivially
# satisfied by construction and the completeness check reduces to
# validating that the generation site still spells the CHILDOP macro
# it claims to.  The denylist is still needed for direction 1 (picker
# op has no rotation slot) and the OMIT-FROM-PICKER tag still marks
# def rows that should not participate in the picker at all.

set -u

NAME="check-alt-op-rotation"
ROOT="${REPO_ROOT:-$(pwd)}"
CHILD_C="$ROOT/child/child-altop-pick.c"
DENYLIST="$ROOT/scripts/check-static/alt-op-rotation.denylist"
CHILDOP_DEF="$ROOT/include/childop.def"

if [ ! -r "$CHILD_C" ]; then
	echo "FAIL: $NAME: cannot read $CHILD_C" >&2
	exit 1
fi
if [ ! -r "$CHILDOP_DEF" ]; then
	echo "FAIL: $NAME: cannot read $CHILDOP_DEF" >&2
	exit 1
fi

# Extract the CHILD_OP_* tokens that appear inside the body of a named
# C-initializer block (between the opening `<name>[...] = {` line and
# the matching `};`).  Restricting extraction to the table braces is
# important: case labels, helper lookups, and case-of-switch usages
# elsewhere in child.c reference the same constants and would otherwise
# pollute the set.
#
# Emits tokens in source order, one per line, WITHOUT de-duplication.
# Callers that want a set pipe through `sort -u`; callers that want to
# detect duplicates keep the raw stream.
extract_table_ops_raw() {
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
	' "$src"
}

# Extract the first CHILDOP() / CHILDOP_SENTINEL() argument (the
# CHILD_OP_* enum tag) from each row of include/childop.def.  Rows are
# one-per-line and always begin at column 0; the first argument is the
# fully-qualified enum name, so no transformation is needed.  Both the
# CHILDOP and CHILDOP_SENTINEL rows contribute to DEF_OPS so denylist
# entries that document the sentinel op (CHILD_OP_SYSCALL) are not
# flagged as stale; the picker's PICK_OPS derivation then removes the
# sentinel explicitly.  Emits raw (undeduplicated) tokens in source
# order so the direction-3 duplicate check has something to bite on.
extract_def_ops_raw() {
	local src="$1"
	awk '
		/^[[:space:]]*CHILDOP(_SENTINEL)?[[:space:]]*\(/ {
			line = $0
			# Strip comments.
			gsub(/\/\*.*\*\//, "", line)
			gsub(/\/\/.*$/, "", line)
			if (match(line, /CHILD_OP_[A-Z0-9_]+/) > 0) {
				print substr(line, RSTART, RLENGTH)
			}
		}
	' "$src"
}

ROT_OPS_RAW="$(extract_table_ops_raw alt_op_rotation "$CHILD_C")"
ROT_OPS="$(printf '%s\n' "$ROT_OPS_RAW" | sort -u)"
DEF_OPS_RAW="$(extract_def_ops_raw "$CHILDOP_DEF")"
DEF_OPS="$(printf '%s\n' "$DEF_OPS_RAW" | sort -u)"

# pick_op_type_table[] is generated from childop.def via X-macro expansion
# in child/child-altop-pick.c, so the picker table membership is exactly
# the set of CHILDOP() rows (the CHILDOP_SENTINEL row -- CHILD_OP_SYSCALL
# -- is excluded because CHILDOP_SENTINEL is redefined to nothing at the
# picker's include site).  Verify the generation site is still spelt as
# expected, then derive PICK_OPS from the def rows.
if ! grep -q 'pick_op_type_table\[\][[:space:]]*=[[:space:]]*{' "$CHILD_C" \
   || ! awk '
	/pick_op_type_table\[\][[:space:]]*=[[:space:]]*\{/ { in_tbl = 1; next }
	in_tbl && /^\};/ { in_tbl = 0; exit }
	in_tbl && /^#[[:space:]]*include[[:space:]]+"childop\.def"/ { found = 1; exit }
	END { exit !found }
' "$CHILD_C"; then
	echo "FAIL: $NAME: pick_op_type_table[] in $CHILD_C does not #include \"childop.def\" -- picker/def generation link is broken" >&2
	exit 1
fi
PICK_OPS_RAW="$(printf '%s\n' "$DEF_OPS_RAW" | grep -v '^CHILD_OP_SYSCALL$' || true)"
PICK_OPS="$(printf '%s\n' "$PICK_OPS_RAW" | sort -u)"

if [ -z "$PICK_OPS" ]; then
	echo "FAIL: $NAME: pick_op_type_table[] derived from $CHILDOP_DEF produced no CHILD_OP_* tokens" >&2
	exit 1
fi
if [ -z "$ROT_OPS" ]; then
	echo "FAIL: $NAME: alt_op_rotation[] body produced no CHILD_OP_* tokens" >&2
	exit 1
fi
if [ -z "$DEF_OPS" ]; then
	echo "FAIL: $NAME: include/childop.def produced no CHILDOP() rows" >&2
	exit 1
fi

# Parse the denylist.  Every non-blank, non-comment line contributes:
#
#   - Its first whitespace token to DENY_OPS (used by the coverage
#     check, direction 1).
#   - If it carries an `OMIT-FROM-PICKER:` tag anywhere on the line,
#     its first token additionally contributes to OMIT_OPS (used by
#     the completeness check, direction 2).  OMIT-FROM-PICKER entries
#     are also valid coverage-check entries -- a childop deliberately
#     left out of the picker is trivially not in the rotation either.
DENY_OPS=""
OMIT_OPS=""
if [ -r "$DENYLIST" ]; then
	DENY_OPS="$(sed -e 's/#.*$//' -e 's/[[:space:]]\+$//' "$DENYLIST" \
		| awk 'NF { print $1 }' \
		| sort -u)"
	OMIT_OPS="$(sed -e 's/#.*$//' -e 's/[[:space:]]\+$//' "$DENYLIST" \
		| awk 'NF && /OMIT-FROM-PICKER:/ { print $1 }' \
		| sort -u)"
fi

# Direction 1 (coverage): pick ops must be in rotation ∪ denylist.
COVERED="$(printf '%s\n%s\n' "$ROT_OPS" "$DENY_OPS" | sort -u)"
MISSING="$(comm -23 <(printf '%s\n' "$PICK_OPS") <(printf '%s\n' "$COVERED"))"

# Direction 2 (completeness): def ops must be in picker ∪ omit-list.
DEF_COVERED="$(printf '%s\n%s\n' "$PICK_OPS" "$OMIT_OPS" | sort -u)"
DEF_MISSING="$(comm -23 <(printf '%s\n' "$DEF_OPS") <(printf '%s\n' "$DEF_COVERED"))"

# Direction 3 (uniqueness): every op in pick_op_type_table[] once.
DUPES="$(printf '%s\n' "$PICK_OPS_RAW" | sort | uniq -d)"

# Stale denylist = denylist entries no longer in pick_op_type_table[]
# AND not tagged OMIT-FROM-PICKER (OMIT entries are legitimately absent
# from the picker by design).  Advisory only.
NON_OMIT_DENY="$(comm -23 <(printf '%s\n' "$DENY_OPS") <(printf '%s\n' "$OMIT_OPS"))"
STALE="$(comm -23 <(printf '%s\n' "$NON_OMIT_DENY") <(printf '%s\n' "$PICK_OPS"))"

# Stale OMIT: OMIT-FROM-PICKER entries that aren't in childop.def at
# all (op renamed or removed).  Advisory.
STALE_OMIT="$(comm -23 <(printf '%s\n' "$OMIT_OPS") <(printf '%s\n' "$DEF_OPS"))"

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

def_missing_count=0
if [ -n "$DEF_MISSING" ]; then
	def_missing_count="$(printf '%s\n' "$DEF_MISSING" | wc -l)"
	{
		echo "  $def_missing_count childop(s) declared in include/childop.def are absent from pick_op_type_table[]:"
		printf '%s\n' "$DEF_MISSING" | sed 's/^/    /'
		echo "  fix: either add a pick_op_type_table[] slot in child/child-altop-pick.c (the op is silently"
		echo "       defaulting to CHILD_OP_SYSCALL in the random picker today), OR add a line to"
		echo "       scripts/check-static/alt-op-rotation.denylist with an"
		echo "       'OMIT-FROM-PICKER: <reason>' tag documenting why the op is deliberately excluded."
	} >&2
fi

dupe_count=0
if [ -n "$DUPES" ]; then
	dupe_count="$(printf '%s\n' "$DUPES" | wc -l)"
	{
		echo "  $dupe_count childop(s) appear more than once in pick_op_type_table[]:"
		printf '%s\n' "$DUPES" | sed 's/^/    /'
		echo "  fix: remove the duplicate slot(s) in child/child-altop-pick.c."
		echo "       A duplicate CHILD_OP_* silently displaces another op -- either the second"
		echo "       designator overwrites the first slot's assignment, or the duplicated op"
		echo "       occupies a slot that would otherwise have carried a different (now missing) op."
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

stale_omit_count=0
if [ -n "$STALE_OMIT" ]; then
	stale_omit_count="$(printf '%s\n' "$STALE_OMIT" | wc -l)"
	{
		echo "  note: $stale_omit_count OMIT-FROM-PICKER denylist entry/entries reference ops absent from include/childop.def (consider pruning):"
		printf '%s\n' "$STALE_OMIT" | sed 's/^/    /'
	} >&2
fi

fail=0
[ "$missing_count" -gt 0 ] && fail=1
[ "$def_missing_count" -gt 0 ] && fail=1
[ "$dupe_count" -gt 0 ] && fail=1

if [ "$fail" -ne 0 ]; then
	echo "FAIL: $NAME: missing=$missing_count def_missing=$def_missing_count dupes=$dupe_count"
	exit 1
fi

pick_count="$(printf '%s\n' "$PICK_OPS" | wc -l)"
rot_count="$(printf '%s\n' "$ROT_OPS" | wc -l)"
def_count="$(printf '%s\n' "$DEF_OPS" | wc -l)"
deny_count=0
[ -n "$DENY_OPS" ] && deny_count="$(printf '%s\n' "$DENY_OPS" | wc -l)"

echo "PASS: $NAME (pick=$pick_count, rotation=$rot_count, denylist=$deny_count, def=$def_count, dupes=0)"
exit 0
