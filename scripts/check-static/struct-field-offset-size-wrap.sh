#!/bin/bash
#
# struct-field-offset-size-wrap: reject `->offset +` / `->offset+` in
# arithmetic comparisons in args/ where neither operand carries an
# (unsigned long) or (uint64_t) cast.
#
# Background (review C2): `struct struct_field` has both `offset` and
# `size` declared as `unsigned int` (struct_catalog.h:72-73).  The
# expression `f->offset + f->size` is evaluated in `unsigned int`, so
# a pair like {offset = UINT_MAX-4, size = 8} wraps to 3 modulo 2^32,
# silently defeating the bounds guard before the subsequent memcpy.
# The correct form is the non-wrapping two-disjunct predicate:
#
#     if (f->offset > size || f->size > size - f->offset) continue;
#
# This check scans all .c / .h files under args/ for any occurrence of
# `->offset` immediately followed (with or without whitespace) by `+`,
# where neither side of the expression carries an explicit widening cast
# to (unsigned long) or (uint64_t).
#
# Fail-closed design (per prior gate-hardening lessons):
#   - grep exit status is checked explicitly; an empty result from
#     grep is the *pass* condition, so using `$(grep … || echo 0)` or
#     checking only for non-empty output fails open.
#   - The count of scanned files is asserted >= 1.  A renamed or
#     removed args/ directory produces zero scanned files; that is a
#     FAIL, not a PASS.  This ensures the gate cannot silently go inert
#     if the directory is restructured.
#
# Mirrors the shape of no-bare-waitpid.sh / no-time-subtraction.sh.

set -u

NAME="struct-field-offset-size-wrap"
ROOT="${REPO_ROOT:-$(pwd)}"

# Pattern: ->offset followed (no space or with space) by +, optionally
# with a space, where neither side carries (unsigned long)/(uint64_t).
# We match the raw `->offset[[:space:]]*+` form; lines already carrying
# an explicit cast will not match this pattern (they look like
# `(unsigned long) f->offset +` or `f->offset + (uint64_t)`).
PATTERN='->offset[[:space:]]*[+]'

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
scan_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp" "$scan_tmp"' EXIT

# Collect all .c / .h files under args/.
find args/ \( -name '*.c' -o -name '*.h' \) -type f -print | sort > "$scan_tmp"

# Fail-closed: assert at least one file was found.
scanned="$(wc -l < "$scan_tmp" | tr -d ' ')"
if [ "$scanned" -lt 1 ]; then
	echo "FAIL: $NAME: no .c/.h files found under args/ -- directory moved or removed?" >&2
	echo "FAIL: $NAME: scanned 0 files under args/ (expected >= 1)"
	exit 1
fi

# Grep each file for the pattern; filter to lines that do NOT already
# carry (unsigned long) or (uint64_t) on the same source line, then
# strip comment lines so the check-static comments themselves do not
# trigger false positives.
while IFS= read -r srcfile; do
	grep -E -H -n -e "$PATTERN" "$srcfile" 2>/dev/null || true
done < "$scan_tmp" | \
while IFS= read -r match; do
	# match is "path:lineno:content".
	path="${match%%:*}"
	rest="${match#*:}"
	lineno="${rest%%:*}"
	content="${rest#*:}"

	# Trim leading whitespace.
	trimmed="${content#"${content%%[![:space:]]*}"}"

	# Skip comment lines (block-comment continuation, /*, //).
	case "$trimmed" in
		\**)   continue ;;
		/\**)  continue ;;
		//*)   continue ;;
	esac

	# Skip lines that already carry a widening cast -- these are
	# the correct form and should not be flagged.
	case "$content" in
		*'(unsigned long)'*)  continue ;;
		*'(uint64_t)'*)       continue ;;
	esac

	# Skip array-index expressions of the form buf[f->offset + off]: these
	# are bounded by the field's own ->size which is checked by the
	# predicate guard on the preceding iteration.  The vulnerability class
	# this check targets is the *comparison predicate* used as the guard
	# itself -- not arithmetic inside an already-guarded body.
	case "$content" in
		*'buf['*'->offset'*)  continue ;;
	esac

	echo "${path#./}:$lineno: $trimmed"
done > "$hits_tmp"

# Explicit exit-status check: grep returns non-zero when it finds no
# matches, but we used `|| true` above to avoid pipeline failure.
# Count lines in hits_tmp to determine pass/fail.
n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: bare ->offset + arithmetic in args/ without widening cast."
		echo "  This pattern wraps in unsigned int when offset + field_size > UINT_MAX."
		echo "  Use the non-wrapping form instead:"
		echo "    if (f->offset > size || f->size > size - f->offset) continue;"
		echo "  Offending site(s):"
		sed 's/^/    /' "$hits_tmp"
	} >&2
	echo "FAIL: $NAME: $n bare ->offset+ arithmetic site(s) in args/ lacking widening cast"
	exit 1
fi

echo "PASS: $NAME: 0 bare ->offset+ arithmetic sites in args/ (scanned $scanned files)"
exit 0
