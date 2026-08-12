#!/bin/bash
#
# dead-arm-detect: warn about switch-on-random-selector blocks that lack
# CHILDOP_ARM_ENTER instrumentation.
#
# DETECTION LOGIC
# ---------------
# A "switch-on-random-selector" file is one that:
#
#   (a) contains a call to rnd_modulo_u32() -- the canonical probabilistic
#       picker used in childops and net/ grammar helpers; and
#
#   (b) contains a multi-arm dispatch on the result, in one of three shapes:
#
#       Direct switch:
#           switch (rnd_modulo_u32(N)) { ... }
#
#       Indirect switch (intermediate variable):
#           unsigned int pick = rnd_modulo_u32(N);
#           ...
#           switch (pick) { ... }
#
#       Ternary / if-chain (no switch keyword):
#           unsigned int arm = rnd_modulo_u32(N);
#           s->use_x = (arm == 1) ? 1U : 0U;
#           s->use_y = (arm == 2) ? 1U : 0U;
#       or equivalently via if (arm == N) / if (var == N) chains.
#
#       The indirect and ternary/if-chain heuristics are intentionally
#       loose: false positives are acceptable for a WARN gate.  A file
#       that uses rnd_modulo_u32 for something other than multi-arm
#       dispatch (e.g. array indexing) can suppress individual call-site
#       warnings with the opt-out annotation described below.
#
# A file in this class that does NOT call CHILDOP_ARM_ENTER is a candidate
# dead-arm source: if any dispatch arm is unreachable the run-time stats
# will look identical to "ran and found nothing" and the dead arm will go
# undetected until manual review.
#
# SCOPE
# -----
# Checked: all .c files under the repo root.
# Skipped: .h headers (arm_entered_* lives in headers, not in code that
#          dispatches).
#
# SEVERITY / RATCHET
# ------------------
# The gate maintains a baseline file (dead-arm-baseline.txt, committed
# alongside this script) that records the WARN list on the first run.
# Subsequent runs:
#   warn_count > baseline_count  => FAIL  (new un-instrumented files added)
#   warn_count <= baseline_count => WARN  (within baseline; exit 0)
#   baseline absent              => write baseline, PASS
#
# This turns the warning list from a permanently-ignored dump into a
# one-way ratchet: the count can only go down.  When all un-instrumented
# files have been addressed, tighten to FAIL unconditionally.
#
# See Documentation/check-static.md for the PASS/FAIL/WARN exit convention.

set -u

NAME="dead-arm-detect"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

warn_list="$tmp/warns"
: > "$warn_list"

# Walk every .c file under the repo root.
while IFS= read -r srcfile; do
	# ---- (a) must reference rnd_modulo_u32 ----
	grep -q 'rnd_modulo_u32' "$srcfile" 2>/dev/null || continue

	# ---- opt-out annotation: /* dead-arm-detect: not a multi-arm dispatch */
	#      placed on the same line as a rnd_modulo_u32() call marks that call
	#      as a non-dispatch use (e.g. array indexing).  Lines carrying the
	#      annotation are excluded before the N-sum below, so one annotation
	#      suppresses exactly one call site. ----

	# ---- (b) must have a dispatch that uses the result ----
	#
	# Three shapes are recognised:
	#   Direct switch:    switch[[:space:]]*([[:space:]]*rnd_modulo_u32
	#   Indirect switch:  file has both `= rnd_modulo_u32(` and `switch (`
	#   Ternary/if-chain: file has `= rnd_modulo_u32(` and either a
	#                     ternary operator following a comparison (`)==N) ?`)
	#                     or an if-chain equality test (`if.*==N`)
	#
	# The variable name is not tracked across shapes -- false positives on
	# files that use rnd_modulo_u32 for non-dispatch purposes are acceptable
	# for a WARN gate (suppress with the opt-out annotation above).
	has_switch=0
	if grep -qE 'switch[[:space:]]*\([[:space:]]*rnd_modulo_u32' "$srcfile" 2>/dev/null; then
		has_switch=1
	elif grep -qE '=[[:space:]]*rnd_modulo_u32\(' "$srcfile" 2>/dev/null &&
	     grep -qE 'switch[[:space:]]*\(' "$srcfile" 2>/dev/null; then
		has_switch=1
	elif grep -qE '=[[:space:]]*rnd_modulo_u32\(' "$srcfile" 2>/dev/null &&
	     { grep -qE '\)[[:space:]]*\?[[:space:]]' "$srcfile" 2>/dev/null ||
	       grep -qE 'if[[:space:]]*\(.*==[[:space:]]*[0-9]' "$srcfile" 2>/dev/null; }; then
		has_switch=1
	fi
	[ "$has_switch" -eq 1 ] || continue

	# ---- (c) skip if CHILDOP_ARM_ENTER count >= sum of literal arm counts.
	#      For each rnd_modulo_u32(N) call with a literal integer N, the
	#      selector covers N arms; sum those N values across all non-opted-out
	#      call sites.  A fully-instrumented file must have at least one
	#      CHILDOP_ARM_ENTER per arm.  Counting call sites (the old approach)
	#      under-counted: a file with one rnd_modulo_u32(16) call and one
	#      CHILDOP_ARM_ENTER would satisfy "1 >= 1" despite 15 un-tracked arms.
	#
	#      Limitation: rnd_modulo_u32(expr) calls where the argument is a
	#      runtime variable or expression (e.g. weight-table pickers that
	#      compute the modulus from a table cardinality) contribute 0 to N_sum
	#      and are not checked here.  Detecting those patterns requires
	#      cross-function data-flow analysis and is out of scope for this gate. ----
	arm_count=$(grep -c 'CHILDOP_ARM_ENTER' "$srcfile" 2>/dev/null); arm_count=${arm_count:-0}
	N_sum=$(grep -v 'dead-arm-detect: not a multi-arm dispatch' "$srcfile" 2>/dev/null | \
	        grep -oE 'rnd_modulo_u32\([0-9]+' | \
	        grep -oE '[0-9]+$' | \
	        awk '{s+=$1} END {print s+0}')
	N_sum=${N_sum:-0}
	[ "$N_sum" -le 0 ] && continue   # no literal-N dispatch calls (all non-literal or all opted-out)
	[ "$arm_count" -ge "$N_sum" ] && continue  # coverage looks complete

	# ---- survivor: emit a warning entry ----
	printf '%s\n' "${srcfile#./}" >> "$warn_list"

done < <(git ls-files '*.c' | sort)

warn_count="$(wc -l < "$warn_list" | tr -d ' ')"

if [ "$warn_count" -gt 0 ]; then
	{
		echo "  $NAME: $warn_count file(s) have multi-arm dispatch on rnd_modulo_u32"
		echo "  (switch, ternary-chain, or if-chain) without CHILDOP_ARM_ENTER"
		echo "  instrumentation.  These are CANDIDATES for dead-arm blind spots --"
		echo "  review each dispatch block, add arm_entered_* fields to the subsystem"
		echo "  stats struct, and call CHILDOP_ARM_ENTER at the top of every arm."
		echo "  See include/arm-tracking.h for usage."
		echo ""
		echo "  Un-instrumented files:"
		sed 's/^/    /' "$warn_list"
		echo ""
		echo "  To silence a legitimate false positive (e.g. rnd_modulo_u32"
		echo "  used for array indexing, not multi-arm dispatch): add a"
		echo "  /* dead-arm-detect: not a multi-arm dispatch */ comment"
		echo "  on the same line as each non-dispatch rnd_modulo_u32 call."
		echo "  One annotation suppresses one call; files with mixed dispatch"
		echo "  and non-dispatch uses are handled correctly."
	} >&2
fi

# ---- Baseline ratchet ----
#
# dead-arm-baseline.txt pins the warn population.  The count must not grow.
baseline_file="$ROOT/scripts/check-static/dead-arm-baseline.txt"

if [ ! -f "$baseline_file" ]; then
	cp "$warn_list" "$baseline_file"
	echo "PASS: $NAME: baseline created ($warn_count file(s) noted; ratchet now active)"
	exit 0
fi

baseline_count="$(wc -l < "$baseline_file" | tr -d ' ')"

if [ "$warn_count" -gt "$baseline_count" ]; then
	echo "FAIL: $NAME: $warn_count un-instrumented file(s) exceeds baseline of $baseline_count" \
	     "-- new files must add CHILDOP_ARM_ENTER or carry a dead-arm-detect opt-out annotation"
	exit 1
fi

if [ "$warn_count" -eq 0 ]; then
	echo "PASS: $NAME: all dispatch-on-rnd_modulo_u32 files use CHILDOP_ARM_ENTER"
else
	echo "WARN: $NAME: $warn_count file(s) missing CHILDOP_ARM_ENTER" \
	     "(within baseline of $baseline_count; see stderr)"
fi
exit 0
