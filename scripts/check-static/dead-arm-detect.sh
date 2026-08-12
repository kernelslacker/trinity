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
#   (b) contains a switch() statement that dispatches on the result,
#       either directly:
#
#           switch (rnd_modulo_u32(N)) { ... }
#
#       or via an intermediate variable:
#
#           unsigned int pick = rnd_modulo_u32(N);
#           ...
#           switch (pick) { ... }
#
# A file in this class that does NOT call CHILDOP_ARM_ENTER is a candidate
# dead-arm source: if any switch arm is unreachable the run-time stats will
# look identical to "ran and found nothing" and the dead arm will go
# undetected until manual review.
#
# SCOPE
# -----
# Checked: childops/**/*.c and net/**/*.c
# Skipped: test files, .h headers (arm_entered_* lives in headers, not
#          in code that dispatches), scripts, stats/ (the dump side).
#
# SEVERITY
# --------
# WARN only (exit 0) -- this is a forward-detection gate, not an enforcement
# gate.  The goal is to flag new code for a reviewer to annotate; once the
# arm count is known the developer adds arm_entered_* fields and
# CHILDOP_ARM_ENTER calls, then the warning disappears.
#
# When all un-instrumented files have been addressed, tighten to FAIL.
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

# Walk every .c file under childops/ and net/.
while IFS= read -r srcfile; do
	# ---- (a) must reference rnd_modulo_u32 ----
	grep -q 'rnd_modulo_u32' "$srcfile" 2>/dev/null || continue

	# ---- opt-out annotation count: each /* dead-arm-detect: not a
	#      multi-arm dispatch */ comment marks one rnd_modulo_u32 call
	#      as a non-dispatch use (e.g. array indexing).  Count them and
	#      subtract from the effective dispatch count rather than
	#      exempting the whole file. ----
	optout_count=$(grep -c 'dead-arm-detect: not a multi-arm dispatch' "$srcfile" 2>/dev/null); optout_count=${optout_count:-0}

	# ---- (b) must have a switch() that dispatches on the result ----
	#
	# Two shapes:
	#   Direct:   switch[[:space:]]*([[:space:]]*rnd_modulo_u32
	#   Indirect: file has both `= rnd_modulo_u32(` and a `switch (`
	#             (the variable name is not checked at this grain --
	#             false positives on files that use rnd_modulo_u32 for
	#             non-switch purposes are acceptable for a WARN gate)
	has_switch=0
	if grep -qE 'switch[[:space:]]*\([[:space:]]*rnd_modulo_u32' "$srcfile" 2>/dev/null; then
		has_switch=1
	elif grep -qE '=[[:space:]]*rnd_modulo_u32\(' "$srcfile" 2>/dev/null &&
	     grep -qE 'switch[[:space:]]*\(' "$srcfile" 2>/dev/null; then
		has_switch=1
	fi
	[ "$has_switch" -eq 1 ] || continue

	# ---- (c) skip if CHILDOP_ARM_ENTER count >= effective dispatch count.
	#      Effective dispatch count = rnd_modulo_u32( occurrences minus
	#      per-call opt-out annotations.  Files where arm_count < effective
	#      dispatch count are partially instrumented and must not be silently
	#      exempted as the old whole-file check would have done. ----
	arm_count=$(grep -c 'CHILDOP_ARM_ENTER' "$srcfile" 2>/dev/null); arm_count=${arm_count:-0}
	rnd_count=$(grep -c 'rnd_modulo_u32(' "$srcfile" 2>/dev/null); rnd_count=${rnd_count:-0}
	effective_rnd=$(( rnd_count - optout_count ))
	[ "$effective_rnd" -le 0 ] && continue   # all uses annotated non-dispatch
	[ "$arm_count" -ge "$effective_rnd" ] && continue  # coverage looks complete

	# ---- survivor: emit a warning entry ----
	printf '%s\n' "${srcfile#./}" >> "$warn_list"

done < <(find childops net -name '*.c' -type f 2>/dev/null | sort)

warn_count="$(wc -l < "$warn_list" | tr -d ' ')"

if [ "$warn_count" -gt 0 ]; then
	{
		echo "  $NAME: $warn_count file(s) have switch-on-rnd_modulo_u32"
		echo "  dispatch without CHILDOP_ARM_ENTER instrumentation."
		echo "  These are CANDIDATES for dead-arm blind spots -- review"
		echo "  each switch block, add arm_entered_* fields to the subsystem"
		echo "  stats struct, and call CHILDOP_ARM_ENTER at the top of every"
		echo "  case arm.  See include/arm-tracking.h for usage."
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
	echo "WARN: $NAME: $warn_count file(s) missing CHILDOP_ARM_ENTER (see stderr)"
	exit 0
fi

echo "PASS: $NAME: all switch-on-rnd_modulo_u32 files use CHILDOP_ARM_ENTER"
exit 0
