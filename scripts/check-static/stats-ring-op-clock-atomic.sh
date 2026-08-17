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
ws_hits_tmp="$(mktemp)"
ws_strip_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp" "$grep_err_tmp" "$ws_hits_tmp" "$ws_strip_tmp"' EXIT

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

# _ws_is_whole_struct_write LINE NAME
#
# Returns 0 (true) when LINE contains a whole-struct write to a
# struct stats_ring pointer whose C identifier is NAME — specifically:
#
#   memset( NAME , ...)  — whole-struct zero (first arg bare NAME, no ->)
#   memcpy( NAME , ...)  — whole-struct copy as destination
#   *NAME = ...          — struct-value assignment through pointer
#
# Returns 1 (false) for sub-member writes:
#   memset(NAME->slots, ...)  — sub-member only; lossless_op_count intact
#   memset(other_var, ...)    — different variable / struct entirely
#
# Pattern rationale:
#   'NAME[[:space:]]*,' matches identifier NAME followed immediately by
#   optional whitespace then a comma — i.e. end of the first argument.
#   'NAME->' cannot match because '->' is not '[[:space:]]' or ','.
#   '\*NAME[[:space:]]*=[^=]' matches struct-deref assignment but not ==.
#
# NAME is anchored dynamically per file by scanning for declarations of
# the form 'struct stats_ring * NAME', so aliases ('r', 'sr', etc.) are
# caught as well as the canonical 'ring'.
_ws_is_whole_struct_write() {
	local _line="$1" _name="$2"
	echo "$_line" | grep -qE \
		"memset[[:space:]]*\([[:space:]]*\*?${_name}[[:space:]]*,|memcpy[[:space:]]*\([[:space:]]*\*?${_name}[[:space:]]*,|\*${_name}[[:space:]]*=[^=]"
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

# --- Whole-struct-write check ---
# A memset/memcpy/struct-assign whose destination is a whole struct
# stats_ring (rather than a named sub-member like ring->slots) clobbers
# lossless_op_count non-atomically while the parent reads it via
# __atomic_load_n(&ring->lossless_op_count, __ATOMIC_RELAXED) — a C11
# data race and UB.  The comment guard in stats_ring_init() is not a gate.
#
# Scope: production .c/.h files that reference struct stats_ring.  As of
# this writing, stats/stats-ring.c is the only production .c with struct
# stats_ring instances; the pattern is nonetheless applied to all files
# so any future addition is caught automatically.
#
# Patterns flagged (matched against every name declared as struct stats_ring *):
#   memset( NAME ,  -- whole-struct zero  (first arg bare pointer, no ->)
#   memcpy( NAME ,  -- whole-struct copy  (destination is bare pointer)
#   *NAME = ...     -- struct-value assignment through a pointer
#
# Patterns NOT flagged (sub-member or unrelated-struct writes):
#   memset(NAME->slots, ...)   -- sub-member only
#   memset(shm_published, ...) -- targets a different struct entirely
#
# The name set is built per-file from declarations of the form
# 'struct stats_ring * NAME', so aliases ('r', 'sr', etc.) are detected
# as well as the canonical 'ring'.  Files with no such declarations are
# skipped (no typed locals → no whole-struct races possible).

while IFS= read -r srcfile; do
	nf="${srcfile#./}"
	case "$nf" in
		tests/*) continue ;;
	esac
	# Only scan files that actually reference struct stats_ring.
	grep -qE 'struct[[:space:]]+stats_ring\b' "$srcfile" || continue

	# Type-anchor: extract every variable name declared as struct stats_ring *.
	# Anchoring on the type rather than the literal identifier 'ring' ensures
	# that aliases like 'r', 'sr', or any other local pointer are also checked.
	mapfile -t _ws_names < <(
		grep -oE 'struct[[:space:]]+stats_ring[[:space:]]*\*[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)' "$srcfile" \
		| grep -oE '[A-Za-z_][A-Za-z0-9_]*$'
	)
	# No typed locals → no whole-struct races possible for this file.
	[ "${#_ws_names[@]}" -gt 0 ] || continue

	# Strip // line comments before scanning (same as _is_plain_lossless_access
	# does upstream) so a commented-out memset does not false-positive.
	sed 's|//[^"]*$||g' "$srcfile" > "$ws_strip_tmp"

	for _ws_name in "${_ws_names[@]}"; do
		ws_grep_out="$(grep -nE \
			"memset[[:space:]]*\([[:space:]]*\*?${_ws_name}[[:space:]]*,|memcpy[[:space:]]*\([[:space:]]*\*?${_ws_name}[[:space:]]*,|\*${_ws_name}[[:space:]]*=[^=]" \
			"$ws_strip_tmp")"
		[ -n "$ws_grep_out" ] || continue

		while IFS= read -r rawline; do
			lineno="${rawline%%:*}"
			content="${rawline#*:}"
			trimmed="${content#"${content%%[![:space:]]*}"}"
			# Skip comment lines.  Use [^a-zA-Z_] after the leading '*' to
			# avoid silently dropping code lines like '*ring = *other;'
			# (which start with '*' followed by an identifier character).
			# '\*[^a-zA-Z_]*)' matches block-comment bodies ('* text', '*/')
			# but not struct-deref expressions.
			case "$trimmed" in
				\*[^a-zA-Z_]*) continue ;;
				/\**) continue ;;
				//*)  continue ;;
			esac
			# Skip pointer declarations: 'struct stats_ring *NAME = ...' is
			# a variable initialisation, not a whole-struct store through a
			# pointer.  The '\*NAME =' pattern matches both forms; exclude
			# the declaration form so only actual dereference-assigns remain.
			echo "$trimmed" | grep -qE \
				"struct[[:space:]]+stats_ring[[:space:]]*\*[[:space:]]*${_ws_name}[[:space:]]*=" \
				&& continue
			echo "${nf}:${lineno}: ${trimmed}"
		done <<< "$ws_grep_out"
	done
done < <(find . \( -name '*.c' -o -name '*.h' \) -type f -not -path './.git/*' -print | sort) \
     >> "$ws_hits_tmp"

ws_n="$(wc -l < "$ws_hits_tmp" | tr -d ' ')"
if [ "$ws_n" -gt 0 ]; then
	{
		echo "  $NAME: whole-struct write to struct stats_ring detected"
		echo "  A memset/memcpy/struct-assign targeting a whole struct stats_ring"
		echo "  clobbers lossless_op_count non-atomically while the parent reads it via"
		echo "    __atomic_load_n(&ring->lossless_op_count, __ATOMIC_RELAXED)"
		echo "  This is a C11 data race and UB.  Use per-member initialisation as"
		echo "  stats_ring_init() does and explicitly preserve lossless_op_count."
		echo "  The comment guard in stats_ring_init() is not a gate."
		echo "  Offending site(s):"
		sed 's/^/    /' "$ws_hits_tmp"
		echo "  fix: replace whole-struct zero/copy with per-member initialisation;"
		echo "       never zero lossless_op_count (run-monotonic op clock, survives respawn)"
	} >&2
	echo "FAIL: $NAME: $ws_n whole-struct stats_ring write(s) found"
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

# Whole-struct-write self-test: verify _ws_is_whole_struct_write() classifies
# fixture lines correctly.  Six fixtures:
#   1. memset(ring, ...)          -- whole-struct zero       -- FAIL (name=ring)
#   2. memcpy(ring, ...)          -- whole-struct copy       -- FAIL (name=ring)
#   3. *ring = *other             -- struct deref assignment -- FAIL (name=ring)
#   4. memset(ring->slots, ...)   -- sub-member only        -- PASS (not flagged)
#   5. memset(shm_published, ...) -- unrelated struct       -- PASS (not flagged)
#   6. memset(r, ...)             -- alias pointer name 'r'  -- FAIL (name=r)
#      Fixture 6 detects the pre-fix anchor deficiency: the old hard-coded
#      'ring' pattern would miss a pointer declared as 'struct stats_ring *r'.
_ws_st_fails=0

# Fixture 1: memset whose first arg is a bare stats_ring pointer -- FAIL.
if ! _ws_is_whole_struct_write \
	'memset(ring, 0, sizeof(*ring));' ring; then
	echo "FAIL: $NAME: ws-self-test: memset(ring,...) wrongly accepted" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

# Fixture 2: memcpy whose destination is a bare stats_ring pointer -- FAIL.
if ! _ws_is_whole_struct_write \
	'memcpy(ring, other, sizeof(*ring));' ring; then
	echo "FAIL: $NAME: ws-self-test: memcpy(ring,...) wrongly accepted" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

# Fixture 3: struct-value assignment through a stats_ring pointer -- FAIL.
if ! _ws_is_whole_struct_write \
	'*ring = *other;' ring; then
	echo "FAIL: $NAME: ws-self-test: *ring=*other wrongly accepted" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

# Fixture 4: memset targeting a sub-member (ring->slots) -- must NOT trip.
if _ws_is_whole_struct_write \
	'memset(ring->slots, 0, sizeof(ring->slots));' ring; then
	echo "FAIL: $NAME: ws-self-test: memset(ring->slots,...) wrongly flagged" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

# Fixture 5: memset targeting a different struct -- must NOT trip.
if _ws_is_whole_struct_write \
	'memset(shm_published, 0, sizeof(*shm_published));' ring; then
	echo "FAIL: $NAME: ws-self-test: memset(shm_published,...) wrongly flagged" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

# Fixture 6: whole-struct zero via an alias pointer name 'r' -- FAIL.
# This is the negative fixture that exposes the pre-fix anchor deficiency:
# the old hard-coded 'ring' pattern would accept memset(r,...) even when
# 'r' is declared as 'struct stats_ring *r = ...'.  The fixed predicate
# anchors on the type-extracted name and must catch this.
if ! _ws_is_whole_struct_write \
	'memset(r, 0, sizeof(*r));' r; then
	echo "FAIL: $NAME: ws-self-test: memset(r,...) with alias name 'r' wrongly accepted" >&2
	_ws_st_fails=$((_ws_st_fails + 1))
fi

if [ "$_ws_st_fails" -gt 0 ]; then
	echo "FAIL: $NAME: ws-self-test: $_ws_st_fails whole-struct-write classification(s) wrong"
	exit 1
fi
echo "PASS: $NAME: ws-self-test: whole-struct-write predicate correctly classifies all 6 fixture lines"

echo "PASS: $NAME: 0 plain lossless_op_count accesses ($scanned files scanned)"
exit 0
