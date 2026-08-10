#!/bin/bash
#
# childop-grandchild-fork: flag fork() child branches in .c files whose child
# body does NOT contain CHILDOP_GRANDCHILD_ENTER(), either directly or via a
# call to a function that starts with CHILDOP_GRANDCHILD_ENTER().
#
# Scope: the whole source tree (not just childops/).  Sites outside childops/
# that have been audited and determined NOT to be grandchild-capable are
# listed in the AUDITED_NON_GRANDCHILD exclusion block below.  The rationale
# mirrors 9add45f15030 which widened the lock gate for the same reason:
# userns throwaway grandchild callbacks and exec-fork helpers can live
# anywhere in the tree.
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
#   satisfies NEITHER:
#     a. The child branch body (braced block or single statement) contains
#        CHILDOP_GRANDCHILD_ENTER() directly, nor
#     b. The child branch body consists of a call to a function defined
#        in the same file whose body starts with CHILDOP_GRANDCHILD_ENTER().
#
# Call-site forms scanned (outer pass):
#   (a) VAR = fork()              -- assignment form (original)
#   (b) if (fork() == 0) { ... } -- direct conditional form (now covered)
#   (c) if (!fork()) { ... }      -- negation conditional form (now covered)
#
# Remaining unscanned forms (out of scope; see future work):
#   - fork() used as switch() argument or inside else-branch condition
#   - Assignment-form fork() whose child branch appears beyond the 40-line
#     scan window (window miss)
#   - fork() in macro arguments or multi-statement comma expressions
# These are rare in the childops/ tree; the gate emits UNPARSED:<file>:<line>
# for any assignment-form fork() whose child branch it cannot locate, so they
# are visible rather than silently skipped.
#
# Output format (one line per finding, fed into the keyed baseline):
#   file:line          -- uncovered child branch (line is the if-branch line)
#   UNPARSED:file:line -- fork() site whose child branch the scanner could not
#                         locate (unrecognised pattern or window miss)
#
# Keyed baseline: scripts/check-static/childop-grandchild-fork.baseline
# Each entry is one "file:line" or "UNPARSED:file:line" string.  Any result
# not present in the baseline fails the gate.  Stale baseline entries (listed
# but no longer produced by the scanner) also fail, to enforce hygiene.
# To regenerate after an intentional change: run with --regen.
#
# Note: the _exit() heuristic used by childop-grandchild-this-child.sh is not
# used here; we do not attempt to determine grandchild intent -- we flag any
# fork child branch missing the macro unconditionally.

set -u

NAME="childop-grandchild-fork"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/childop-grandchild-fork.baseline"

# Legacy count baseline kept for reference; no longer used for comparison.
COUNT_BASELINE="$ROOT/scripts/check-static/childop-grandchild-fork.count.baseline"

MODE="check"
case "${1:-}" in
	--regen) MODE="regen" ;;
esac

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
#   Pass 2: find fork() call sites, locate the associated child branch,
#           and check whether it is covered by the macro either directly
#           in the branch body or via a call to a covered function.
#
#           Three call-site forms are recognised:
#             (a) VAR = fork()             -- assignment form
#             (b) if (fork() == 0) { ... } -- direct conditional
#             (c) if (!fork()) { ... }      -- negation conditional
#           For assignment form, UNPARSED:<file>:<line> is emitted if the
#           inner scan cannot locate a child branch within 40 lines.

# -----------------------------------------------------------------------
# AUDITED_NON_GRANDCHILD: fork() sites outside childops/ that have been
# reviewed and confirmed NOT to produce a grandchild worker in the beacon
# sense (i.e. the fork child does not run syscalls as trinity's grandchild
# and does not need CHILDOP_GRANDCHILD_ENTER).
#
# Each entry is a repo-relative file path.  Rationale per file:
#
#   fds/scratch_block.c
#     run_mkfs_ext4(): one-shot exec helper.  Forks to run mkfs.ext4 against
#     a scratch device during pre-fork single-threaded setup.  The child
#     immediately exec()s an external binary; it is not a trinity grandchild
#     worker and carries no beacon state.
#
#   health/kmsg-monitor.c
#     kmsg_monitor_start(): infrastructure daemon fork.  The comment in that
#     file notes it is "intentionally NOT registered in pids[]/
#     running_childs/childdata -- it is infrastructure, not a fuzz child".
#     The child runs the kmsg polling helper loop, never syscall fuzzing;
#     it is not a trinity grandchild worker.
#
#   utils/pc_format.c
#     pc_symbolize_fork(): addr2line exec helper.  Forks a short-lived
#     subprocess that exec()s addr2line to resolve a PC address and pipes
#     the result back.  The child is not a trinity grandchild worker.
#
#   utils/self_cgroup_fork.c
#     self_cgroup_fork_into_workload(): produces the regular trinity CHILD
#     process (pid returned to spawn_child()).  The fork()d process becomes
#     a first-generation child, not a grandchild; CHILDOP_GRANDCHILD_ENTER
#     is inapplicable here.  The scanner emits UNPARSED for this site
#     because there is no if (pid == 0) branch -- the child falls through
#     and the function returns pid (0) to the caller.
# -----------------------------------------------------------------------

while IFS= read -r srcfile; do
	relfile="${srcfile#"$ROOT"/}"

	# Skip audited non-grandchild sites (see AUDITED_NON_GRANDCHILD above).
	case "$relfile" in
		fds/scratch_block.c|\
		health/kmsg-monitor.c|\
		utils/pc_format.c|\
		utils/self_cgroup_fork.c)
			continue ;;
	esac

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

	# ----------------------------------------------------------------
	# check_if_body: given that an "if (...)" starts at if_line_idx,
	# determine whether the body of that branch is covered by
	# CHILDOP_GRANDCHILD_ENTER() (directly or via a covered function).
	# Returns 1 if covered, 0 if not.
	#
	# if_sl is the already-comment-stripped text of lines[if_line_idx].
	# n     is the total number of lines.
	# ----------------------------------------------------------------
	function check_if_body(if_line_idx, if_sl, n,
	                        rest, is_braced, k, brace_line,
	                        d, sl3, tmp3, arr4, t3,
	                        covered) {
		covered = 0

		# Strip the "if (...)" prefix to get what follows on this line.
		rest = if_sl
		sub(/if[[:space:]]*\([^)]*\)[[:space:]]*/, "", rest)
		rest = trim(rest)

		# Determine if body is braced or single-statement.
		is_braced = (rest ~ /^\{/)

		if (!is_braced && rest == "") {
			# Body is on the next non-empty line.
			for (k = if_line_idx + 1; k <= n && k <= if_line_idx + 3; k++) {
				t3 = trim(strip_comment(lines[k]))
				if (t3 == "") continue
				rest = t3
				break
			}
			is_braced = (rest ~ /^\{/)
		}

		if (is_braced) {
			# Braced block: scan it for CHILDOP_GRANDCHILD_ENTER
			# or a call to any covered function.
			# Find which line has the opening {.
			brace_line = if_line_idx
			if (strip_comment(lines[if_line_idx]) !~ /\{/) {
				for (k = if_line_idx + 1; k <= n && k <= if_line_idx + 3; k++) {
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
				tmp3 = rest
				while (match(tmp3,
				    /([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\(/,
				    arr4)) {
					if (arr4[1] in covered_funcs) { covered = 1; break }
					tmp3 = substr(tmp3, RSTART + RLENGTH - 1)
				}
			}
		}

		return covered
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
		# Three call-site forms are recognised:
		#
		#   (a) VAR = fork()             -- assignment form
		#       Scan ahead (up to 40 lines) for if (VAR == 0) / if (!VAR)
		#       at the same relative brace depth.  If not found, emit
		#       UNPARSED:<file>:<forkline>.
		#
		#   (b) if (fork() == 0) { ... } -- direct conditional
		#   (c) if (!fork()) { ... }      -- negation conditional
		#       The fork site IS the child branch; check its body
		#       immediately.
		#
		# For the assignment form the child branch is the first
		# "if (VAR == 0)" or "if (!VAR)" encountered at the SAME brace
		# depth as the fork() call (depth 0 relative to the fork() line).
		# ============================================================
		for (i = 1; i <= n; i++) {
			sl = strip_comment(lines[i])

			# --------------------------------------------------------
			# Classify the line: assignment form, direct conditional,
			# or neither.
			# --------------------------------------------------------
			is_assign = (sl ~ /=[[:space:]]*fork[[:space:]]*\(\)/)
			is_cond   = (sl ~ /if[[:space:]]*\([[:space:]]*fork[[:space:]]*\(\)[[:space:]]*==[[:space:]]*0/ ||
			             sl ~ /if[[:space:]]*\([[:space:]]*!fork[[:space:]]*\(\)/)

			if (!is_assign && !is_cond)
				continue

			# --------------------------------------------------------
			# Direct conditional: if (fork() == 0) or if (!fork()).
			# The fork site IS the child branch at line i.
			# --------------------------------------------------------
			if (is_cond) {
				if (!check_if_body(i, sl, n))
					print file ":" i
				continue
			}

			# --------------------------------------------------------
			# Assignment form: VAR = fork()
			# Extract the pid variable name, then scan ahead.
			# --------------------------------------------------------
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
			# If we exhaust the window without finding a child branch,
			# emit UNPARSED:<file>:<forkline>.
			rel_depth   = 0
			child_found = 0
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
					child_found = 1
					if (!check_if_body(j, sl2, n))
						print file ":" j
					break
				}

				# Stop if we encounter a new fork() at depth 0.
				if (sl2 ~ /=[[:space:]]*fork[[:space:]]*\(\)/) break

				# Track brace depth for the next iteration.
				rel_depth += brace_delta(sl2)
			}

			# If no child branch was found in the scan window, report
			# the fork site as unparsed so it is visible rather than
			# silently skipped.
			if (!child_found)
				print "UNPARSED:" file ":" i
		}
	}
	' "$srcfile" >> "$tmp_out"

done < <(find "$ROOT" -name '*.c' | sort)

# -----------------------------------------------------------------------
# Regen mode: write the current output as the new baseline.
# -----------------------------------------------------------------------
if [ "$MODE" = "regen" ]; then
	{
		printf '# childop-grandchild-fork keyed baseline\n'
		printf '# Each entry is "file:line" (uncovered child branch) or\n'
		printf '# "UNPARSED:file:line" (fork() site whose child branch the scanner\n'
		printf '# could not locate).  Regenerated by: %s --regen\n' \
		       "$(basename "$0")"
		if [ -s "$tmp_out" ]; then
			cat "$tmp_out"
		fi
	} > "$BASELINE"
	line_count=$(wc -l < "$BASELINE")
	echo "REGEN: $NAME: wrote $line_count line(s) to ${BASELINE#"$ROOT"/}"
	exit 0
fi

# -----------------------------------------------------------------------
# Check mode: load keyed baseline and compare.
# -----------------------------------------------------------------------
if [ ! -r "$BASELINE" ]; then
	echo "FAIL: $NAME: cannot read keyed baseline from $BASELINE" >&2
	echo "  run: bash scripts/check-static/childop-grandchild-fork.sh --regen" >&2
	exit 1
fi

declare -A BASELINE_KEYS=()
while IFS= read -r entry; do
	[ -z "$entry" ] && continue
	case "$entry" in \#*) continue ;; esac
	BASELINE_KEYS["$entry"]=1
done < "$BASELINE"

# Collect results, classify as new (not in baseline) or seen.
declare -A SEEN_KEYS=()
new_findings=()

while IFS= read -r line; do
	[ -z "$line" ] && continue
	SEEN_KEYS["$line"]=1
	if [ -z "${BASELINE_KEYS[$line]+x}" ]; then
		new_findings+=("$line")
	fi
done < "$tmp_out"

# Stale baseline entries: listed but no longer produced by the scanner.
stale_baseline=()
for key in "${!BASELINE_KEYS[@]}"; do
	if [ -z "${SEEN_KEYS[$key]+x}" ]; then
		stale_baseline+=("$key")
	fi
done

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
		echo "  (listed in baseline but no longer produced by the scanner):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
		echo "  fix: run  bash scripts/check-static/childop-grandchild-fork.sh --regen"
		echo "  and commit the updated baseline alongside the code change."
	} >&2
	echo "FAIL: $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
	exit 1
fi

if [ "${#new_findings[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#new_findings[@]} new finding(s) not in baseline:"
		for e in "${new_findings[@]}"; do echo "    $e"; done
		echo "  For 'file:line' entries:"
		echo "    insert CHILDOP_GRANDCHILD_ENTER() as the first statement of"
		echo "    each child branch body (or at the top of the called worker"
		echo "    function).  See existing propagation commits for the pattern."
		echo "  For 'UNPARSED:file:line' entries:"
		echo "    the scanner could not locate a child branch; inspect the"
		echo "    fork() site and either fix the pattern (assignment form with"
		echo "    VAR == 0 / !VAR check within 40 lines) or add the entry to"
		echo "    the baseline if the site is intentionally unscanned."
		echo "  After resolving or grandfathering all entries, run:"
		echo "    bash scripts/check-static/childop-grandchild-fork.sh --regen"
	} >&2
	echo "FAIL: $NAME: ${#new_findings[@]} new finding(s) not in baseline"
	exit 1
fi

total=${#SEEN_KEYS[@]}
baselined=${#BASELINE_KEYS[@]}
echo "PASS: $NAME (findings=$total, baselined=$baselined)"
exit 0
