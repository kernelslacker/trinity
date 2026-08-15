#!/bin/bash
#
# stats-ring-op-clock-atomic: reject any plain (non-atomic) access to
# lossless_op_count in production C files.
#
# lossless_op_count is accessed from two concurrent contexts:
#   - child (writer) via __atomic_fetch_add(..., __ATOMIC_RELAXED)
#   - parent (reader) via __atomic_load_n(..., __ATOMIC_RELAXED)
#
# Mixing a plain store/increment with an __atomic_load_n is a C11 data
# race and therefore undefined behaviour, regardless of whether the
# generated code happens to be correct on the target architecture.
#
# This gate fails if any .c file outside the explicit allow-list
# contains "lossless_op_count" on a non-comment line where __atomic_
# does NOT directly govern the field reference itself (i.e. lossless_op_count
# appears as an argument to the intrinsic, or the field is assigned from
# an intrinsic whose argument list contains lossless_op_count).
#
# Allow-listed paths (by explicit case statement, NOT bare grep -v):
#
#   tests/*            -- single-threaded fixture; all accesses use
#                         __atomic_ for model consistency, but even if
#                         they did not the harness is not concurrent
#
# The grep pattern '(->|\.)lossless_op_count' is token-precise: it
# matches only field-access expressions (-> or . dereference) and not
# bare identifiers such as prev_lossless_op_count[] or diagnostic
# strings that merely contain the field name as a substring.  This
# avoids the need for a whole-file exemption for stats/stats-ring.c
# (which contains the only __atomic_load_n reader) and keeps that site
# inside coverage.
#
# Comment lines (trimmed prefix: *, /*, //) are skipped globally for
# all files, since a comment that mentions the field name is not an
# access and must not produce a false positive.
#
# Fail-open guards:
#   - Assert at least one .c file was scanned (a glob matching nothing
#     or a missing directory must not silently pass)
#   - Check grep exit status explicitly; an empty result is NOT a PASS
#     until the scanned-file count has been verified

set -u

NAME="stats-ring-op-clock-atomic"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
grep_err_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp" "$grep_err_tmp"' EXIT

scanned=0

while IFS= read -r srcfile; do
	# Normalise to a path without leading ./
	nf="${srcfile#./}"

	# Explicit allow-list.
	case "$nf" in
		tests/*) continue ;;
	esac

	scanned=$((scanned + 1))

	# Walk lines with a field-access expression for lossless_op_count.
	# The pattern requires -> or . before the field name, so bare
	# identifiers like prev_lossless_op_count[] do not match.
	#
	# Capture stdout and exit status separately so that a real grep
	# failure (status ≥2: unreadable file, bad regex, I/O error) is
	# never silently treated as "no match".  Status 0 = match(es)
	# found; status 1 = no match (clean); status ≥2 = error → FAIL.
	grep_out="$(grep -nE '(->|\.)lossless_op_count' "$srcfile")"
	grep_status=$?
	if [ "$grep_status" -ge 2 ]; then
		echo "  $NAME: grep error (status $grep_status) scanning $nf" >&2
		echo "$nf" >> "$grep_err_tmp"
		continue
	fi

	# Status 1 (no match) means no candidate lines; nothing to inspect.
	[ -n "$grep_out" ] || continue

	while IFS= read -r rawline; do
		# rawline is "lineno:content".
		lineno="${rawline%%:*}"
		content="${rawline#*:}"

		# Trim leading whitespace for the comment-line test.
		trimmed="${content#"${content%%[![:space:]]*}"}"

		# Skip block-comment body lines, banner openers, line comments.
		# This covers all files, not just stats-ring.c.
		case "$trimmed" in
			\**)  continue ;;
			/\**) continue ;;
			//*)  continue ;;
		esac

		# Line is a non-comment source line.  It is valid only if
		# __atomic_ directly governs the lossless_op_count field
		# reference: either the intrinsic takes lossless_op_count as an
		# argument, or the field name precedes an __ATOMIC_ order token
		# (i.e. is itself the argument being qualified).  A bare
		# substring test for __atomic_ anywhere on the line admits false
		# passes when an unrelated intrinsic appears on the same line
		# (e.g. a plain store to lossless_op_count whose RHS loads a
		# different field atomically).
		if echo "$content" | grep -qE '__atomic_[a-z_]+\([^)]*lossless_op_count'; then
			continue
		fi

		# Surviving lines are plain (non-atomic) accesses -- FAIL.
		echo "${nf}:${lineno}: ${trimmed}"
	done <<< "$grep_out"
done < <(find . \( -name '*.c' -o -name '*.h' \) -type f -not -path './.git/*' -print | sort) \
     >> "$hits_tmp"

# Assert we actually scanned at least one file.
if [ "$scanned" -eq 0 ]; then
	{
		echo "  $NAME: no source files were scanned"
		echo "  (directory missing, glob matched nothing, or all files allow-listed)"
		echo "  A zero-file scan must not silently pass."
	} >&2
	echo "FAIL: $NAME: 0 files scanned"
	exit 1
fi

# If any grep invocation returned status ≥2 (real error), fail now.
# An empty result that came from a grep error is NOT a PASS.
if [ -s "$grep_err_tmp" ]; then
	{
		echo "  $NAME: grep exited with error status (≥2) while scanning:"
		sed 's/^/    /' "$grep_err_tmp"
		echo "  A grep error is not the same as no match; treating as scan failure."
	} >&2
	echo "FAIL: $NAME: grep scan error(s) in $(wc -l < "$grep_err_tmp" | tr -d ' ') file(s)"
	exit 1
fi

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: plain (non-atomic) lossless_op_count access found"
		echo "  All production sites must use:"
		echo "    __atomic_fetch_add(&..->lossless_op_count, 1, __ATOMIC_RELAXED)"
		echo "  The parent reads the field with __atomic_load_n; a plain store"
		echo "  races with that load and is C11 UB."
		echo "  Offending site(s):"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: replace plain ++ / = with __atomic_fetch_add(..., __ATOMIC_RELAXED)"
		echo "       (RELAXED is sufficient; the child is the sole writer)"
	} >&2
	echo "FAIL: $NAME: $n plain lossless_op_count access(es) ($scanned files scanned)"
	exit 1
fi

echo "PASS: $NAME: 0 plain lossless_op_count accesses ($scanned files scanned)"

# Self-test: verify the anchored atomicity predicate accepts genuinely
# atomic accesses and rejects a plain assignment whose RHS happens to
# contain an unrelated __atomic_ call on the same line.
#
# Three fixture lines are tested:
#   1. __atomic_fetch_add(&ring->lossless_op_count, ...) -- must be accepted
#   2. __atomic_load_n(&ring->lossless_op_count, ...) -- must be accepted
#   3. ring->lossless_op_count = __atomic_load_n(&other_field, ...) -- must
#      be REJECTED: the atomic intrinsic governs other_field, not
#      lossless_op_count; the assignment itself is a plain (non-atomic) write.
_st_pat='__atomic_[a-z_]+\([^)]*lossless_op_count'
_st_fails=0
# Fixture lines 1 and 2: atomic intrinsic takes lossless_op_count as an
# argument -- predicate must accept them (grep matches => continue in loop).
for _st_line in \
	'__atomic_fetch_add(&ring->lossless_op_count, 1, __ATOMIC_RELAXED);' \
	'__atomic_load_n(&ring->lossless_op_count, __ATOMIC_RELAXED);'
do
	if ! echo "$_st_line" | grep -qE "$_st_pat"; then
		echo "FAIL: $NAME: self-test: anchored predicate wrongly rejected: $_st_line" >&2
		_st_fails=$((_st_fails + 1))
	fi
done
# Fixture line 3: plain assignment to lossless_op_count; the __atomic_ call
# on the RHS operates on a different field entirely.  Predicate must reject.
if echo 'ring->lossless_op_count = __atomic_load_n(&other_field, __ATOMIC_RELAXED);' | grep -qE "$_st_pat"; then
	echo "FAIL: $NAME: self-test: anchored predicate wrongly accepted plain assignment with unrelated atomic" >&2
	_st_fails=$((_st_fails + 1))
fi
if [ "$_st_fails" -gt 0 ]; then
	echo "FAIL: $NAME: self-test: $_st_fails predicate classification(s) wrong"
	exit 1
fi
echo "PASS: $NAME: self-test: anchored predicate correctly classifies all 3 fixture lines"
exit 0
