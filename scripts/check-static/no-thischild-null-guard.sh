#!/bin/bash
#
# no-thischild-null-guard: reject NULL-sentinel guards on this_child() inside
# childops/.
#
# Background: this_child() never returns NULL when called from within a
# child process.  The fast path in dispatch/pids.c is a self-comparison
# (cached_pid == getpid()); grandchildren inherit cached_childno and
# cached_pid via COW; and include/pids.h documents this property as
# intentional and load-bearing.  Any guard of the form
#
#     child = this_child();
#     op = child ? child->op_type : NR_CHILD_OP_TYPES;
#
# or the inline variant
#
#     op = this_child() ? this_child()->op_type : NR_CHILD_OP_TYPES;
#
# is therefore dead.  The sentinel branch (NR_CHILD_OP_TYPES) is never
# reached and the NULL-ternary misleads readers into thinking this_child()
# may return NULL.
#
# The correct form for childops is the direct dereference:
#
#     const enum child_op_type op = this_child()->op_type;
#
# What is flagged (childops/ only):
#   1. A local variable V assigned from this_child() in any C source file
#      under childops/, where that same file contains V followed by '?'
#      (ternary null-guard: V ? V->member : sentinel).
#   2. A direct expression: this_child() followed by '?' on the same token
#      boundary (excluding assert() calls).
#   3. Direct NULL comparisons: this_child() == NULL / this_child() != NULL
#      outside of an assert() argument.
#
# What is NOT flagged:
#   - Code outside childops/ (args/, health/, cmp_hints/, etc. can
#     legitimately call this_child() in parent context where NULL is
#     possible).
#   - assert(this_child() != NULL): a runtime invariant check is not a
#     dead guard.
#   - Lines that are purely comments.
#   - Files listed in the grandfathered baseline below (existing
#     violations that pre-date this check).  The baseline should shrink
#     over time, never grow.
#
# Exit 0 if no new violations; exit 1 if any.

set -u

NAME="no-thischild-null-guard"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/$NAME.baseline"

if [ ! -d "$ROOT/childops" ]; then
	echo "PASS: $NAME (no childops/ directory)"
	exit 0
fi

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		# strip inline comments
		entry="${entry%%  #*}"
		entry="${entry%%	#*}"
		entry="${entry%"${entry##*[! ]}"}"
		if [[ -v GRANDFATHERED["$entry"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $entry" >&2
			exit 1
		fi
		GRANDFATHERED["$entry"]=1
	done < "$BASELINE"
fi

tmp_out=$(mktemp)
trap 'rm -f "$tmp_out"' EXIT

while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"

	# Skip grandfathered files entirely.
	[ "${GRANDFATHERED[$rel]+set}" = "set" ] && continue

	# Pass 1 — indirect ternary: a variable assigned from this_child()
	# that later appears in a ternary (VAR ?) in the same file.
	# We collect variable names from "= this_child()" lines, then
	# scan for "VAR ?" or "VAR?" on a non-comment line.
	while IFS= read -r varname; do
		[ -z "$varname" ] && continue
		# Search the file for VARNAME followed by ? on a code line.
		while IFS= read -r match; do
			lineno="${match%%:*}"
			content="${match#*:}"
			trimmed="${content#"${content%%[![:space:]]*}"}"
			case "$trimmed" in
				\**)  continue ;;
				/\**) continue ;;
				//*)  continue ;;
			esac
			echo "${rel}:${lineno}: [indirect ternary on this_child() result] ${trimmed}"
		done < <(grep -n -E "${varname}[[:space:]]*\\?" "$srcfile" 2>/dev/null)
	done < <(grep -oP '(?:\*\s*)?\K\w+(?=\s*=\s*this_child\(\))' "$srcfile" 2>/dev/null | sort -u)

	# Pass 2 — direct patterns on this_child() itself.
	while IFS= read -r match; do
		lineno="${match%%:*}"
		content="${match#*:}"
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**)  continue ;;
			/\**) continue ;;
			//*)  continue ;;
		esac
		# Exclude assert() — a runtime invariant check is intentional.
		case "$trimmed" in
			*assert*) continue ;;
		esac
		echo "${rel}:${lineno}: [direct null-check on this_child()] ${trimmed}"
	done < <(grep -n -E \
		'this_child\(\)[[:space:]]*[?]|this_child\(\)[[:space:]]*(==|!=)[[:space:]]*NULL|!this_child\(\)|if[[:space:]]*\([[:space:]]*this_child\(\)[[:space:]]*\)' \
		"$srcfile" 2>/dev/null)

done < <(find "$ROOT/childops" -name '*.c' -type f | sort) > "$tmp_out"

n="$(wc -l < "$tmp_out" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: dead this_child() NULL guard(s) in childops/:"
		sed 's/^/    /' "$tmp_out"
		echo "  fix: this_child() never returns NULL in child context."
		echo "       Replace 'child = this_child(); op = child ? child->op_type : NR_CHILD_OP_TYPES;'"
		echo "       with 'const enum child_op_type op = this_child()->op_type;'"
		echo "       See include/pids.h for the COW-invariant guarantee."
	} >&2
	echo "FAIL: $NAME: $n dead null-guard(s) on this_child() in childops/"
	exit 1
fi

echo "PASS: $NAME: 0 new this_child() null-guards in childops/ ($(wc -l < "$BASELINE" 2>/dev/null || echo 0) grandfathered)"
exit 0
