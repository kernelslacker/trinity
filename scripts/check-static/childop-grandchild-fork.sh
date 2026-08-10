#!/bin/bash
#
# childop-grandchild-fork: flag fork() child branches in childops/ .c files
# whose child body does NOT contain CHILDOP_GRANDCHILD_ENTER(), either directly
# or via a call to a function that starts with CHILDOP_GRANDCHILD_ENTER().
#
# Background: b2a7eda686e8 ("health: propagate grandchild beacon-gate to all
# fork sites") introduced CHILDOP_GRANDCHILD_ENTER() and propagated it to 8 of
# 38 fork-producing childops/ files.  38f6bde2c954 ("supervisor: add missing
# CHILDOP_GRANDCHILD_ENTER to three fork workers") added three more.
# Fork()'d grandchild workers that skip the macro can run child_fault_handler()
# with in_grandchild==0, stamping the PARENT worker's crash beacon, writing to
# the parent's buglog, and racing the parent's memfd.
#
# What is flagged:
#   Any fork() call in a childops/*.c file whose associated child branch
#   (if (VAR == 0) or if (!VAR) following the fork) satisfies NEITHER:
#     a. The child branch body (braced block or single statement) contains
#        CHILDOP_GRANDCHILD_ENTER() directly, nor
#     b. The child branch body consists of a call to a function defined
#        in the same file whose body starts with CHILDOP_GRANDCHILD_ENTER().
#
# Output: one "file:line" per uncovered fork child branch.
#
# Ceiling baseline: scripts/check-static/childop-grandchild-fork.count.baseline
# The gate fails if the current count EXCEEDS the ceiling (no new regressions).
# The ceiling should shrink toward 0 as remaining sites are fixed; it must
# never grow.
#
# Note: the _exit() heuristic used by childop-grandchild-this-child.sh is not
# used here; we do not attempt to determine grandchild intent -- we flag any
# fork child branch missing the macro unconditionally.

set -u

NAME="childop-grandchild-fork"
ROOT="${REPO_ROOT:-$(pwd)}"
COUNT_BASELINE="$ROOT/scripts/check-static/childop-grandchild-fork.count.baseline"

if [ ! -d "$ROOT/childops" ]; then
	echo "PASS: $NAME (no childops/ directory)"
	exit 0
fi

tmp_out=$(mktemp)
trap 'rm -f "$tmp_out"' EXIT

# Process each childops .c file with a per-file gawk invocation.
# gawk runs two logical passes over the file content loaded into lines[]:
#
#   Pass 1: collect function names whose FIRST real statement (after the
#           top-level opening brace) is CHILDOP_GRANDCHILD_ENTER() --
#           these are "covered functions".
#
#   Pass 2: find fork() call sites, locate the associated child branch
#           (if (VAR == 0) / if (!VAR)), and check whether it is covered
#           by the macro either directly in the branch body or via a call
#           to a covered function.

while IFS= read -r srcfile; do
	relfile="${srcfile#"$ROOT"/}"

	gawk -v file="$relfile" '

	# ----------------------------------------------------------------
	# strip_comment: remove // comments (enough for our patterns).
	# ----------------------------------------------------------------
	function strip_comment(line,    i, c, in_str) {
		in_str = 0
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			if (c == "\"") { in_str = !in_str; continue }
			if (in_str) continue
			if (c == "/" && substr(line, i+1, 1) == "/")
				return substr(line, 1, i-1)
		}
		return line
	}

	# ----------------------------------------------------------------
	# brace_delta: net brace count change for a stripped line.
	# ----------------------------------------------------------------
	function brace_delta(line,    i, c, in_str, delta) {
		delta  = 0
		in_str = 0
		for (i = 1; i <= length(line); i++) {
			c = substr(line, i, 1)
			if (c == "\"") { in_str = !in_str; continue }
			if (in_str) continue
			if (c == "{") delta++
			else if (c == "}") delta--
		}
		return delta
	}

	# ----------------------------------------------------------------
	# trim: strip leading/trailing whitespace from s.
	# ----------------------------------------------------------------
	function trim(s) {
		gsub(/^[[:space:]]+/, "", s)
		gsub(/[[:space:]]+$/, "", s)
		return s
	}

	# ----------------------------------------------------------------
	# last_func_name: find the LAST "identifier(" on a line, skipping
	# C keywords and __attribute__.  Used to extract a function name
	# from a definition line such as:
	#   static __attribute__((noreturn)) void funcname(args)
	# ----------------------------------------------------------------
	function last_func_name(line,    tmp, name, cand) {
		name = ""
		tmp  = line
		while (match(tmp, /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(/, arr)) {
			cand = arr[1]
			if (cand != "if"    && cand != "for"     && cand != "while"  &&
			    cand != "switch" && cand != "return"  && cand != "sizeof" &&
			    cand != "typeof" && cand != "defined" && cand != "static" &&
			    cand != "struct" && cand != "union"   && cand != "__attribute__")
				name = cand
			# Advance past this match to find later occurrences.
			tmp = substr(tmp, RSTART + RLENGTH - 1)
		}
		return name
	}

	# ----------------------------------------------------------------
	# is_skip_line: true if a stripped+trimmed line should be skipped
	# when searching for the first real statement in a function body.
	# ----------------------------------------------------------------
	function is_skip_line(t) {
		if (t == "") return 1
		if (t == "{" || t == "}") return 1
		if (substr(t, 1, 2) == "/*" || substr(t, 1, 2) == "//") return 1
		if (t ~ /^\*/) return 1           # continuation of /* block */
		if (t ~ /^__attribute__/) return 1
		return 0
	}

	# ================================================================
	# Main: read all lines, then run the two passes.
	# ================================================================
	{ lines[NR] = $0 }

	END {
		n = NR
		delete covered_funcs

		# ============================================================
		# Pass 1: find functions whose first real statement is the
		# CHILDOP_GRANDCHILD_ENTER() macro.
		# ============================================================
		depth = 0
		for (i = 1; i <= n; i++) {
			sl    = strip_comment(lines[i])
			delta = brace_delta(sl)

			if (depth == 0 && delta > 0) {
				# Entering a top-level scope -- find function name
				# by walking back up to 8 lines.
				func_name = ""
				for (b = i; b >= 1 && b >= i - 8; b--) {
					cand = last_func_name(lines[b])
					if (cand != "") { func_name = cand; break }
				}

				# Scan ahead for first non-trivial statement.
				d2 = delta
				for (j = i + 1; j <= n && j <= i + 20; j++) {
					sl2 = strip_comment(lines[j])
					t2  = trim(sl2)
					if (is_skip_line(t2)) {
						d2 += brace_delta(sl2)
						if (d2 <= 0) break
						continue
					}
					# First real statement found.
					if (t2 ~ /CHILDOP_GRANDCHILD_ENTER/ && func_name != "")
						covered_funcs[func_name] = 1
					break
				}
			}

			depth += delta
			if (depth < 0) depth = 0
		}

		# ============================================================
		# Pass 2: find fork() call sites and their child branches.
		#
		# We scan ahead from each "VAR = fork()" line, tracking brace
		# depth so that return/goto inside error blocks do not cause a
		# premature stop.  The child branch is the first "if (VAR == 0)"
		# or "if (!VAR)" encountered at the SAME brace depth as the
		# fork() call (depth 0 relative to the fork() line).
		# ============================================================
		for (i = 1; i <= n; i++) {
			sl = strip_comment(lines[i])

			# Require a fork() call on the RHS of an assignment.
			if (sl !~ /=[[:space:]]*fork[[:space:]]*\(\)/)
				continue

			# Extract the pid variable name: strip everything from
			# "= fork()" onward, then take the last identifier.
			pid_var = ""
			tmp_sl  = sl
			sub(/[[:space:]]*=[[:space:]]*fork[[:space:]]*\(\).*/, "", tmp_sl)
			if (match(tmp_sl, /([A-Za-z_][A-Za-z0-9_]*)([[:space:]]*)$/, arr))
				pid_var = arr[1]
			if (pid_var == "" || pid_var == "return")
				continue

			# Build match patterns for the child branch condition.
			# We accept: if (... VAR == 0) or if (!VAR)
			# The VAR may be preceded by member-access like "p->" or "*".
			cond_zero = "if[[:space:]]*\\(([^)]*[^A-Za-z0-9_]|)" \
			            pid_var "[[:space:]]*==[[:space:]]*0"
			cond_not  = "if[[:space:]]*\\([[:space:]]*!" pid_var "[[:space:]]*\\)"

			# Scan ahead tracking brace depth relative to fork() line.
			# We stop when:
			#   a. We find the child if-branch at relative depth 0.
			#   b. We see a new fork() assignment at relative depth 0
			#      (this fork() is unrelated; its own branch will be
			#      processed in a later outer-loop iteration).
			#   c. We exceed the scan window (40 lines).
			rel_depth = 0
			for (j = i + 1; j <= n && j <= i + 40; j++) {
				sl2 = strip_comment(lines[j])
				t2  = trim(sl2)

				# Skip blank / pure-comment lines.
				if (t2 == "" || t2 == "{" || t2 == "}" ||
				    substr(t2,1,2) == "//" || substr(t2,1,2) == "/*")
				{
					rel_depth += brace_delta(sl2)
					continue
				}

				# At relative depth > 0 we are inside an inner
				# block (e.g. "if (pid < 0) { ... }"); skip lines
				# within it but keep tracking depth.
				if (rel_depth > 0) {
					rel_depth += brace_delta(sl2)
					continue
				}

				# At relative depth 0: look for the child branch.
				is_child = (sl2 ~ cond_zero || sl2 ~ cond_not)

				if (is_child) {
					child_if_line = j
					covered = 0

					# Strip the "if (...)" prefix to get what follows.
					rest = sl2
					sub(/if[[:space:]]*\([^)]*\)[[:space:]]*/, "", rest)
					rest = trim(rest)

					# Determine if body is braced or single-statement.
					is_braced = (rest ~ /^\{/)

					if (!is_braced && rest == "") {
						# Body is on the next non-empty line.
						for (k = j + 1; k <= n && k <= j + 3; k++) {
							t3 = trim(strip_comment(lines[k]))
							if (t3 == "") continue
							rest = t3
							break
						}
						is_braced = (rest ~ /^\{/)
					}

					if (is_braced) {
						# Braced block: scan it for CHILDOP_GRANDCHILD_ENTER
						# or a call to any covered function (which itself
						# starts with the macro).
						# Find which line has the opening {.
						brace_line = j
						if (strip_comment(lines[j]) !~ /\{/) {
							for (k = j+1; k <= n && k <= j+3; k++) {
								if (strip_comment(lines[k]) ~ /\{/) {
									brace_line = k; break
								}
							}
						}
						# Scan the block.
						d = brace_delta(strip_comment(lines[brace_line]))
						if (strip_comment(lines[brace_line]) ~ /CHILDOP_GRANDCHILD_ENTER/)
							covered = 1
						for (k = brace_line + 1; k <= n && d > 0 && !covered; k++) {
							sl3 = strip_comment(lines[k])
							if (sl3 ~ /CHILDOP_GRANDCHILD_ENTER/) { covered = 1; break }
							# Check for a call to any covered function.
							tmp3 = sl3
							while (match(tmp3, /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(/, arr4)) {
								if (arr4[1] in covered_funcs) { covered = 1; break }
								tmp3 = substr(tmp3, RSTART + RLENGTH - 1)
							}
							d += brace_delta(sl3)
						}
					} else {
						# Single-statement body (no braces).
						# Check for CHILDOP_GRANDCHILD_ENTER directly, or
						# any call to a covered function (including patterns
						# like _exit(covered_func()) ).
						if (rest ~ /CHILDOP_GRANDCHILD_ENTER/) {
							covered = 1
						} else {
							tmp_rest = rest
							while (match(tmp_rest,
							    /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(/,
							    arr3)) {
								if (arr3[1] in covered_funcs) { covered = 1; break }
								tmp_rest = substr(tmp_rest, RSTART + RLENGTH - 1)
							}
						}
					}

					if (!covered)
						print file ":" child_if_line

					break   # one child branch per fork() call
				}

				# Stop if we encounter a new fork() at depth 0.
				if (sl2 ~ /=[[:space:]]*fork[[:space:]]*\(\)/) break

				# Track brace depth for the next iteration.
				rel_depth += brace_delta(sl2)
			}
		}
	}
	' "$srcfile" >> "$tmp_out"

done < <(find "$ROOT/childops" -name '*.c' | sort)

# -----------------------------------------------------------------------
# Count results and enforce ceiling.
# -----------------------------------------------------------------------
if [ -s "$tmp_out" ]; then
	total=$(wc -l < "$tmp_out")
else
	total=0
fi

if [ ! -r "$COUNT_BASELINE" ]; then
	echo "FAIL: $NAME: cannot read count ceiling from $COUNT_BASELINE" >&2
	exit 1
fi

frozen=$(tr -d '[:space:]' < "$COUNT_BASELINE")
if ! [[ "$frozen" =~ ^[0-9]+$ ]]; then
	echo "FAIL: $NAME: malformed ceiling in $COUNT_BASELINE (got: $frozen)" >&2
	exit 1
fi

if [ "$total" -gt "$frozen" ]; then
	{
		echo "  $NAME: $total uncovered fork child branch(es) (ceiling: $frozen):"
		sed 's/^/    /' "$tmp_out"
		echo "  To fix: insert CHILDOP_GRANDCHILD_ENTER() as first statement of each"
		echo "  child branch body (or at the top of the called worker function)."
		echo "  See the existing propagation commits for the pattern."
	} >&2
	echo "FAIL: $NAME: count regressed ($total > ceiling $frozen)"
	exit 1
fi

echo "PASS: $NAME (uncovered=$total, ceiling=$frozen)"
exit 0
