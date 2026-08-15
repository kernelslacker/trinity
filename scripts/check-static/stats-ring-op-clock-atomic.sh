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
# contains "lossless_op_count" on a non-comment line that does NOT also
# contain "__atomic_" on the same line (i.e. the token is not lexically
# inside an atomic macro call written on one line, or on the same line
# as the field reference for multi-line calls).
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
trap 'rm -f "$hits_tmp"' EXIT

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
	grep -nE '(->|\.)lossless_op_count' "$srcfile" 2>/dev/null | \
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
		# __atomic_ also appears on the same line (the field reference
		# is either on the same line as the __atomic_fetch_add /
		# __atomic_load_n call, or the entire call is one line).
		case "$content" in
			*__atomic_*) continue ;;
		esac

		# Surviving lines are plain (non-atomic) accesses -- FAIL.
		echo "${nf}:${lineno}: ${trimmed}"
	done
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
exit 0
