#!/bin/bash
#
# childop-stats-writer-registered: every .c file under childops/ that
# writes shm->stats.<subsys> counters must have a corresponding
# CHILD_OP_* entry in include/childop.def, OR be explicitly listed as
# an infrastructure exemption in this gate's baseline.
#
# Background: trinity's static check suite catches stats fields that
# have no emitter (stats-field-unemitted.sh), but it is blind to the
# dual: a file under childops/ that writes shm->stats counters but
# has no corresponding CHILD_OP_* registration.  Such a file is dead
# code -- its producer path can never be scheduled, so every counter
# it bumps is permanently zero and the shm->stats fields it touches
# appear "live" only because the write exists, not because a caller
# ever reaches it.
#
# The class was proven by childops/net/crafted-icmp-rx.c: six
# shm->stats.icmp_inject.* counters wired, but no CHILD_OP_* entry in
# include/childop.def means the dispatch table never includes it, so
# the functions are unreachable and every counter stays zero.
#
# Detection: for each .c file under childops/ that contains a write to
# shm->stats (via __atomic_add_fetch, __atomic_fetch_add, __atomic_store_n,
# or a direct assignment through the ->stats member), check whether any
# top-level function defined in that file is registered as a dispatch
# function (the third CHILDOP() argument) in include/childop.def.
#
# Legitimate exceptions: carve files whose dispatch function lives in a
# sibling file (called from the sibling's registered entry point) and
# shared infrastructure units (recipe/, netlink utility layers) belong
# here too but are not themselves dispatch entry points.  These are
# listed in the baseline alongside a brief reason.  The baseline should
# shrink over time as carves are reconstituted or infrastructure is
# restructured; it must never grow without explanation.
#
# A file that writes shm->stats, defines no dispatch function, AND is
# not in the baseline is an error: it is either dead code (no caller
# can schedule it) or a missing registration that silences a whole
# family of counters.
#
# A baseline of grandfathered files lives alongside this script as
# childop-stats-writer-registered.baseline (one relative path per line,
# comments with #).  The baseline should shrink over time, never grow.

set -u

NAME="childop-stats-writer-registered"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/childop-stats-writer-registered.baseline"
CHILDOPS_DIR="$ROOT/childops"
CHILDOP_DEF="$ROOT/include/childop.def"

if [ ! -f "$CHILDOP_DEF" ]; then
	echo "FAIL: $NAME: include/childop.def not found" >&2
	exit 1
fi

# Load baseline exemptions (relative paths, one per line, # comments ok).
declare -A GRANDFATHERED=()
declare -A seen=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		# Strip trailing whitespace and inline comments.
		entry="$(sed 's/[[:space:]]#.*$//' <<< "$entry" | sed 's/[[:space:]]*$//')"
		[ -z "$entry" ] && continue
		if [[ -v seen[$entry] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $entry" >&2
			exit 1
		fi
		seen[$entry]=1
		GRANDFATHERED["$entry"]=1
	done < "$BASELINE"
fi

# Phase 1: collect all dispatch function names from include/childop.def.
# The CHILDOP() macro has the form:
#   CHILDOP(enum_name, "name_string", dispatch_fn, uses_outer_bracket, dormant)
# The dispatch_fn is the third comma-separated argument.  NULL entries
# (CHILD_OP_SYSCALL sentinel) are excluded.
DISPATCH_FILE="$(mktemp)"
trap 'rm -f "$DISPATCH_FILE" 2>/dev/null' EXIT

awk '/^CHILDOP\(/ {
	# Remove the macro name and opening paren.
	line = $0
	sub(/^CHILDOP[^(]*\(/, "", line)
	# Split on commas, respecting no nested parens at this level.
	# Field 1 = enum_name, field 2 = name_string, field 3 = dispatch_fn.
	n = split(line, parts, /,/)
	if (n >= 3) {
		fn = parts[3]
		gsub(/[[:space:]]/, "", fn)
		if (fn != "NULL" && fn != "")
			print fn
	}
}' "$CHILDOP_DEF" | LC_ALL=C sort -u > "$DISPATCH_FILE"

dispatch_count=$(wc -l < "$DISPATCH_FILE")
if [ "$dispatch_count" -eq 0 ]; then
	echo "FAIL: $NAME: no dispatch functions found in include/childop.def" >&2
	exit 1
fi

# Phase 2: for each .c file under childops/ that writes shm->stats,
# check if the file defines any dispatch function.
#
# Stats-write heuristic: the file contains shm->stats. (covers both
# direct member access after -> and patterns like shm->stats.subsys.field).
#
# Dispatch-function heuristic: scan non-comment lines for top-level
# function definitions of the form:
#   [qualifiers] identifier(   -- where identifier is at the start of an
#   identifier run immediately before '('
# Then test whether that identifier appears in the dispatch function set.
# This is intentionally conservative: it only matches definitions that
# appear at the start of a line (after optional qualifiers), not nested
# or static helper functions deep inside blocks.

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"

	# Skip files with no shm->stats write.
	grep -q 'shm->stats\.' "$srcfile" || continue

	# Check if any function defined in this file is a dispatch function.
	found=0
	while IFS= read -r fn; do
		if grep -qxF "$fn" "$DISPATCH_FILE"; then
			found=1
			break
		fi
	done < <(
		# Extract top-level function names: any identifier immediately
		# before '(' that appears after return-type tokens on a line that
		# begins with an identifier (not inside a block).  We strip
		# block-comment content and line comments, then look for the
		# pattern: line starts with optional type qualifiers, then an
		# identifier, then '('.
		awk '
		function strip_comments(s,    idx, tail, cidx) {
			if (in_block) {
				idx = index(s, "*/")
				if (idx == 0) return ""
				s = substr(s, idx + 2)
				in_block = 0
			}
			while ((idx = index(s, "/*")) > 0) {
				tail = substr(s, idx + 2)
				cidx = index(tail, "*/")
				if (cidx == 0) {
					in_block = 1
					s = substr(s, 1, idx - 1)
					break
				}
				s = substr(s, 1, idx - 1) " " substr(tail, cidx + 2)
			}
			sub(/\/\/.*$/, "", s)
			return s
		}
		BEGIN { in_block = 0 }
		{
			code = strip_comments($0)
			# Match a top-level function definition: an identifier
			# immediately followed by "(" starting after optional
			# return-type tokens.  The line must begin with a
			# letter (not a space/tab, ruling out most statements
			# inside function bodies).
			if (match(code,
			    /^[a-zA-Z_][a-zA-Z0-9_ *]*[[:space:]]([a-z_][a-z0-9_]*)[[:space:]]*\(/) ||
			    match(code,
			    /^([a-z_][a-z0-9_]*)[[:space:]]*\(/)) {
				# Extract the identifier just before "(".
				s = code
				if (match(s, /[a-z_][a-z0-9_]*[[:space:]]*\(/)) {
					tok = substr(s, RSTART, RLENGTH)
					sub(/[[:space:]]*\($/, "", tok)
					print tok
				}
			}
		}
		' "$srcfile" | LC_ALL=C sort -u
	)

	[ "$found" -eq 1 ] && continue

	# File writes shm->stats but defines no dispatch function.
	# Check the baseline exemption.
	[ -n "${SEEN_KEY[$rel]+x}" ] && continue
	SEEN_KEY["$rel"]=1

	if [ -z "${GRANDFATHERED[$rel]+x}" ]; then
		new_unbaselined+=("$rel")
	fi

done < <(find "$CHILDOPS_DIR" -name '*.c' | LC_ALL=C sort)

# Stale baseline detection: an entry is stale when the file no longer
# writes shm->stats OR the file now defines a registered dispatch
# function (it was wired up and the exemption is obsolete).
stale_baseline=()
for gf_entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$gf_entry]+x}" ]; then
		stale_baseline+=("$gf_entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} childop file(s) write shm->stats.*"
		echo "  but have no corresponding CHILD_OP_* entry in"
		echo "  include/childop.def and are not in the exemption baseline:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo ""
		echo "  Each flagged file is either:"
		echo "    (a) dead code -- the stats writes never execute because"
		echo "        the file has no registered dispatch entry point."
		echo "        Fix: add a CHILD_OP_* row to include/childop.def with"
		echo "        a dispatch function defined in this file, or remove"
		echo "        the dead file if it was superseded."
		echo "    (b) a carve/infrastructure file whose dispatch function"
		echo "        lives in a sibling file (the carve is correctly called"
		echo "        from a registered dispatch entry point)."
		echo "        Fix: add the file path to"
		echo "        scripts/check-static/childop-stats-writer-registered.baseline"
		echo "        with a brief explanation.  The baseline should shrink"
		echo "        over time, never grow."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  ${#stale_baseline[@]} baseline entry/entries are stale"
		echo "  (file no longer writes shm->stats, or now defines a"
		echo "  registered dispatch function):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
		echo "  fix: remove the listed entries from"
		echo "       scripts/check-static/childop-stats-writer-registered.baseline"
	} >&2
	echo "FAIL: $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
	exit 1
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unregistered stats writer(s) not in baseline"
	exit 1
fi

exempted_n=${#GRANDFATHERED[@]}
echo "PASS: $NAME (checked dispatch_fns=${dispatch_count} exempted=${exempted_n})"
exit 0
