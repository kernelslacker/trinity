#!/bin/bash
#
# check-static-doc-parity: every script in scripts/check-static/ must
# have a matching row in Documentation/check-static.md, and every doc
# row must correspond to a real script.
#
# The doc file's "What today's checks enforce" section is
# hand-maintained (the note at the top of that section says as much).
# Without a gate, the list drifts silently: a new check lands with no
# doc row, and by the time a reader notices, half a dozen scripts have
# no explanation of what they enforce.  That is exactly the state
# 17c1420e3d8d ("check-static: gate sfg phase-order invariants") uncovered when it added the sfg-phase-order-invariants
# row -- 22 earlier scripts had no row at all.
#
# The check reads both sides symbolically:
#   * script side: ls scripts/check-static/*.sh, strip the .sh suffix.
#   * doc side:    every line beginning `- \`<name>\`` in
#     Documentation/check-static.md, matching the existing row shape.
# This script gates its own doc row too -- the row is what documents
# what the gate does for a reader picking up the file cold.
#
# A missing doc row (script with no row) is a hard FAIL -- new
# checks must document what they enforce.  A stale doc row (row with
# no script) is also a hard FAIL -- a removed check should not leave
# a dangling row that misleads readers about what the battery
# actually runs.

set -u

NAME="check-static-doc-parity"
ROOT="${REPO_ROOT:-$(pwd)}"
DIR="$ROOT/scripts/check-static"
DOC="$ROOT/Documentation/check-static.md"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$DIR" ] || fail "check-static directory not found: $DIR"
[ -r "$DOC" ] || fail "doc file not found: $DOC"

scripts=$(ls "$DIR"/*.sh 2>/dev/null \
	| xargs -n1 basename \
	| sed 's/\.sh$//' \
	| sort -u)

[ -n "$scripts" ] || fail "no scripts found under $DIR"

# Doc rows have the shape:  - `<name>`: ...
# The leading "- `" anchors on the row form and skips any inline
# `<name>` mention elsewhere in the prose (e.g. cross-references
# inside a row body).
docs=$(grep -oE '^- `[a-z0-9-]+`' "$DOC" \
	| sed -e 's/^- `//' -e 's/`$//' \
	| sort -u)

[ -n "$docs" ] || fail "no doc rows found in $DOC"

missing=$(comm -23 <(printf '%s\n' "$scripts") <(printf '%s\n' "$docs"))
stale=$(comm -13 <(printf '%s\n' "$scripts") <(printf '%s\n' "$docs"))

fail_count=0

if [ -n "$missing" ]; then
	{
		echo "  $NAME: script(s) with no doc row in Documentation/check-static.md:"
		printf '%s\n' "$missing" | sed 's/^/    /'
		echo "  fix: add a row to the 'What today's checks enforce' list"
		echo "       describing what the script gates (match the existing row style)."
	} >&2
	fail_count=$((fail_count + 1))
fi

if [ -n "$stale" ]; then
	{
		echo "  $NAME: doc row(s) with no matching script in scripts/check-static/:"
		printf '%s\n' "$stale" | sed 's/^/    /'
		echo "  fix: remove the row -- it points at a check the battery no longer runs."
	} >&2
	fail_count=$((fail_count + 1))
fi

if [ "$fail_count" -ne 0 ]; then
	n_missing=$(printf '%s\n' "$missing" | grep -c . || true)
	n_stale=$(printf '%s\n' "$stale" | grep -c . || true)
	echo "FAIL: $NAME: $n_missing undocumented script(s), $n_stale stale doc row(s)"
	exit 1
fi

n=$(printf '%s\n' "$scripts" | grep -c . || true)
echo "PASS: $NAME ($n script(s), all documented, no stale rows)"
exit 0
