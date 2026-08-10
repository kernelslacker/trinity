#!/bin/bash
#
# childop-grandchild-this-child: flag this_child() result variables accessed
# with per-process members in a function that also calls _exit(), which is
# the reliable marker of a grandchild-capable worker body.
#
# Background: in a fork()'d grandchild this_child() returns the parent's
# COW-inherited childdata slot (non-NULL).  Reading fork-invariant members
# (op_type, op_nr) through it is safe; reading or writing per-process state
# is not.  See Documentation/this-child-grandchild-reachability.md.
#
# What is flagged:
#   A C function body (tracked by brace depth) that contains ALL of:
#     1. a variable assigned from this_child() (e.g. tc = this_child())
#     2. a call to _exit(
#     3. an access VAR->MEMBER on that variable where MEMBER is not in
#        the fork-invariant set {op_type, op_nr}
#
# What is NOT flagged:
#   - Functions that only access op_type or op_nr through the childdata ptr
#   - Member accesses on unrelated variables (shm->stats, opts->foo, etc.)
#   - Files outside childops/
#
# Exit 0 if no warnings, exit 1 if any.

set -u

NAME="childop-grandchild-this-child"
ROOT="${REPO_ROOT:-$(pwd)}"

if [ ! -d "$ROOT/childops" ]; then
	echo "PASS: $NAME (no childops/ directory)"
	exit 0
fi

tmp_out=$(mktemp)
trap 'rm -f "$tmp_out"' EXIT

while IFS= read -r srcfile; do
	gawk -v file="${srcfile#"$ROOT"/}" '
	BEGIN {
		depth      = 0
		has_exit   = 0
		bad_member = ""
		bad_line   = 0
		split("", tc_vars)   # initialise as array so delete stays array-typed
	}

	{
		# Track brace depth character by character (skip string literals)
		n = split($0, chars, "")
		in_str = 0
		for (i = 1; i <= n; i++) {
			c = chars[i]
			if (c == "\"") { in_str = !in_str; continue }
			if (in_str) continue
			if (c == "{") {
				depth++
			} else if (c == "}") {
				if (depth == 1) {
					# End of top-level function body — emit if flagged
					if (has_exit && bad_member != "" && length(tc_vars) > 0)
						print file ":" bad_line ": this_child() used with per-process member ->" bad_member " in grandchild-capable function"
					# Reset per-function state
					has_exit   = 0
					bad_member = ""
					bad_line   = 0
					delete tc_vars
					split("", tc_vars)   # re-init as array after delete
				}
				if (depth > 0)
					depth--
			}
		}
	}

	depth > 0 {
		# Detect: VARNAME = this_child()
		if (match($0, /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*this_child\(\)/, arr))
			tc_vars[arr[1]] = 1

		# Detect _exit() — marks grandchild-capable function
		if ($0 ~ /_exit\(/)
			has_exit = 1

		# Detect VAR->MEMBER where VAR came from this_child() and MEMBER is per-process
		if (bad_member == "" && length(tc_vars) > 0) {
			tmp = $0
			while (match(tmp, /([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)/, arr)) {
				varname = arr[1]
				member  = arr[2]
				if (varname in tc_vars && member != "op_type" && member != "op_nr") {
					bad_member = member
					bad_line   = NR
					break
				}
				tmp = substr(tmp, RSTART + RLENGTH)
			}
		}
	}
	' "$srcfile" >> "$tmp_out"
done < <(find "$ROOT/childops" -name '*.c' | sort)

if [ -s "$tmp_out" ]; then
	while IFS= read -r line; do
		echo "WARN: $line"
	done < "$tmp_out"
	echo "FAIL: $NAME"
	exit 1
fi

echo "PASS: $NAME"
exit 0
