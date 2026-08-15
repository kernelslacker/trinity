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

# _is_plain_lossless_access LINE
#
# Returns 0 (true) when LINE contains a plain (non-atomic) access to
# lossless_op_count -- i.e. when, after stripping every __atomic_*()
# call expression using balanced-paren matching, any (->|\.)lossless_op_count
# token still remains.  Returns 1 (false) when every access on the line
# is inside an __atomic_ intrinsic.
#
# This is the production predicate.  The self-test below exercises the
# same function directly so that mutating it breaks both production and
# the self-test simultaneously.
#
# Balanced-paren stripping is done with a Python3 one-liner so that
# call expressions containing nested parens (e.g. get_ring(child)->field)
# are handled correctly.  The [^)]* predicate introduced by
# d40b905576e4 ("check-static: anchor lossless_op_count atomicity predicate to field")
# could not cross a ')' and therefore false-rejected such sites, and it
# also false-accepted a plain store whose RHS atomically loads the same
# field (the field name appeared inside the intrinsic's parens on the RHS
# while the LHS write was still plain).
_is_plain_lossless_access() {
	local _stripped
	_stripped="$(printf '%s' "$1" | python3 -c "
import re, sys
s = sys.stdin.read()
while True:
    new_s = ''
    i = 0
    found = False
    while i < len(s):
        m = re.match(r'__atomic_[a-z_]+\\(', s[i:])
        if m:
            j = i + len(m.group()) - 1  # index of the opening '('
            depth = 1
            j += 1
            while j < len(s) and depth > 0:
                if s[j] == '(':
                    depth += 1
                elif s[j] == ')':
                    depth -= 1
                j += 1
            i = j  # skip past the entire __atomic_xxx(...) call
            found = True
        else:
            new_s += s[i]
            i += 1
    if not found:
        break
    s = new_s
print(s, end='')
")"
	echo "$_stripped" | grep -qE '(->|\.)lossless_op_count'
}

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

		# Line is a non-comment source line.  It is valid only if every
		# access to lossless_op_count on the line is inside an __atomic_
		# intrinsic.  _is_plain_lossless_access strips all __atomic_*()
		# call expressions (balanced-paren walk) and checks whether any
		# (->|\.)lossless_op_count token survives.  If none survives,
		# every access was inside an intrinsic and the line is safe.
		if ! _is_plain_lossless_access "$content"; then
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

# Self-test: verify _is_plain_lossless_access() classifies all fixture
# lines correctly.  Runs before the PASS echo so a failing self-test
# cannot produce a PASS line followed by FAIL output.
#
# The self-test calls _is_plain_lossless_access() directly -- the same
# function the walk loop uses -- so any mutation of the production
# predicate immediately breaks the self-test as well.
#
# Five fixture lines:
#   1. __atomic_fetch_add(&ring->lossless_op_count, ...) -- PASS (inside intrinsic)
#   2. __atomic_load_n(&ring->lossless_op_count, ...) -- PASS (inside intrinsic)
#   3. ring->lossless_op_count = __atomic_load_n(&other_field, ...) -- FAIL
#      (intrinsic governs other_field; lossless_op_count LHS is a plain write)
#   4. ring->lossless_op_count = __atomic_load_n(&other->lossless_op_count, ...) -- FAIL
#      (same-field store: field appears in the intrinsic's args on the RHS
#      but the LHS is still a plain write; the old [^)]* predicate falsely
#      accepted this because the field name was visible inside the parens)
#   5. __atomic_fetch_add(&get_ring(child)->lossless_op_count, ...) -- PASS
#      (nested paren in arg; the old [^)]* predicate falsely rejected this
#      because [^)]* cannot cross the ')' from get_ring(child))
_st_fails=0

# Fixtures 1 and 2: every access is inside an __atomic_ intrinsic -- must PASS.
for _st_line in \
	'__atomic_fetch_add(&ring->lossless_op_count, 1, __ATOMIC_RELAXED);' \
	'__atomic_load_n(&ring->lossless_op_count, __ATOMIC_RELAXED);'
do
	if _is_plain_lossless_access "$_st_line"; then
		echo "FAIL: $NAME: self-test: predicate wrongly rejected atomic access: $_st_line" >&2
		_st_fails=$((_st_fails + 1))
	fi
done

# Fixture 3: plain LHS write; atomic on RHS governs a different field -- must FAIL.
if ! _is_plain_lossless_access \
	'ring->lossless_op_count = __atomic_load_n(&other_field, __ATOMIC_RELAXED);'; then
	echo "FAIL: $NAME: self-test: predicate wrongly accepted plain store (unrelated RHS atomic)" >&2
	_st_fails=$((_st_fails + 1))
fi

# Fixture 4 (same-field store): LHS is a plain write; RHS atomically loads
# the *same* field.  The old [^)]* predicate accepted this because the field
# name appeared inside the intrinsic's parens on the RHS.  Must FAIL.
if ! _is_plain_lossless_access \
	'ring->lossless_op_count = __atomic_load_n(&other->lossless_op_count, __ATOMIC_RELAXED);'; then
	echo "FAIL: $NAME: self-test: predicate wrongly accepted same-field plain store" >&2
	_st_fails=$((_st_fails + 1))
fi

# Fixture 5 (nested paren in intrinsic arg): the old [^)]* predicate rejected
# this because it could not cross the ')' from get_ring(child).  Must PASS.
if _is_plain_lossless_access \
	'__atomic_fetch_add(&get_ring(child)->lossless_op_count, 1, __ATOMIC_RELAXED);'; then
	echo "FAIL: $NAME: self-test: predicate wrongly rejected nested-paren atomic access" >&2
	_st_fails=$((_st_fails + 1))
fi

if [ "$_st_fails" -gt 0 ]; then
	echo "FAIL: $NAME: self-test: $_st_fails predicate classification(s) wrong"
	exit 1
fi
echo "PASS: $NAME: self-test: predicate correctly classifies all 5 fixture lines"

echo "PASS: $NAME: 0 plain lossless_op_count accesses ($scanned files scanned)"
exit 0
