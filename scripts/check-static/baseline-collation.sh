#!/bin/bash
#
# baseline-collation: assert that every committed baseline file used by
# a comm(1)/join(1) consumer script is never fed raw to comm/join without
# an in-script sort, and that every directly-sorted committed baseline is
# byte-identical to its own LC_ALL=C sort output.
#
# Background
# ----------
# comm(1) and join(1) require both inputs to be sorted under the *same*
# locale.  When a committed baseline was originally sorted under en_US.UTF-8
# but the gate runs in a C/POSIX shell (CI containers, cron, env-scrubbed
# runners), sort produces a different order, comm silently degrades, and
# set-difference results are wrong.  c481a1c1f5a7 ("dead-arm-detect: pin
# LC_ALL=C so comm runs in consistent collation") fixed one such gate.
# This check prevents the class from recurring.
#
# Consumer detection (operand provenance)
# ----------------------------------------
# A "collation-sensitive consumer" is a script in check-static/ where:
#   (a) a non-comment line assigns a variable to a path of the form
#       $ROOT/scripts/check-static/*.{baseline,txt}, AND
#   (b) the script contains at least one comm(1) or join(1) invocation.
#
# Keying on the ASSIGNMENT (not on the name of the variable that appears
# on the comm/join line) closes the naming-convention hole: a consumer
# using `comm -13 "$BASE2" "$tmp"` where
# `BASE2="$ROOT/scripts/check-static/x.baseline"` is correctly detected
# even though "baseline" does not appear in the variable name on the
# comm line.
#
# Safety check (operand tracking — not proximity)
# -----------------------------------------------
# For each detected consumer, every committed baseline variable (those
# assigned to check-static paths) must NOT appear directly as an operand
# to comm/join.  A raw committed baseline fed to comm skips the sort step
# that guarantees locale-invariant ordering.
#
# Concretely: if the script has
#
#   MYBASE="$ROOT/scripts/check-static/foo.baseline"
#   ...
#   comm -13 "$MYBASE" "$tmp"         ← FAIL: raw committed file to comm
#
# it is UNSAFE.  The correct form sorts first:
#
#   sort "$MYBASE" > "$tmp/sorted"
#   comm -13 "$tmp/sorted" "$tmp/cur" ← OK: committed file pre-sorted
#
# IMPORTANT: export LC_ALL=C is NOT a substitute.
# LC_ALL=C pins the locale for sorts performed *at runtime by the script*.
# It cannot retroactively sort a file committed in a different locale
# order.  A script that has `export LC_ALL=C` but passes the committed
# baseline directly to comm is still UNSAFE and will FAIL this gate.
# LC_ALL=C is a desirable complement — it ensures the in-script sort and
# comm agree on order — but it does not replace the sort step.
#
# Baseline C-sort validation (direct-sort consumers only)
# -------------------------------------------------------
# If the consumer sorts the committed baseline variable directly
# (`sort "$MYBASE" > tmp`, with sort as the first command, not in a
# pipeline receiving the baseline), the committed file must be
# byte-identical to its own LC_ALL=C sort output.
#
# Baselines consumed through comment-stripping pipelines (sed/awk before
# sort) carry intentional section comments that make the raw file
# non-C-sorted by design; those are excluded from this check.
#
# Fail-close
# ----------
# If the consumer list is empty the filter is almost certainly broken
# (the known consumer dead-arm-detect.sh vanished or was restructured).
# Gate fails rather than silently passing with zero checks performed.
#
# Selftest
# --------
# Run with --selftest to exercise the three fail-open checks against
# synthetic fixtures.  Each fixture must exit 1 under the gate.

set -u

NAME="baseline-collation"
ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null)}"
CSDIR="$ROOT/scripts/check-static"

fail() {
	echo "$@" >&2
	_fail=1
}

_fail=0

# ------------------------------------------------------------------
# extract_baseline_vars SCRIPT
#
# Print (one per line, sorted -u) the names of variables that are
# assigned a $ROOT/scripts/check-static/*.{baseline,txt} path on a
# non-comment line.  The ROOT placeholder may be written as $ROOT or
# ${ROOT}; no other root spellings are matched (they would need their
# own assignment patterns and are not used by current consumers).
# ------------------------------------------------------------------
extract_baseline_vars() {
	local script="$1"
	grep -v '^[[:space:]]*#' "$script" \
	| grep -oP '^[[:space:]]*\K[A-Za-z_][A-Za-z0-9_]*(?=="\$\{?ROOT\}?/scripts/check-static/[^"[:space:]]+\.(?:baseline|txt)")' \
	| sort -u
}

# ------------------------------------------------------------------
# has_direct_comm VAR SCRIPT
#
# Return 0 (true) if any non-comment line in SCRIPT that contains a
# comm or join invocation also contains a direct reference to $VAR or
# ${VAR}.  "Direct" means the variable reference is not inside a
# quoted sort sub-expression; for the purpose of this check we simply
# look for the token on the same non-comment line as comm/join.
#
# Returning 0 means the committed baseline variable is being passed
# raw to comm/join — UNSAFE.
# ------------------------------------------------------------------
has_direct_comm() {
	local var="$1" script="$2"
	grep -v '^[[:space:]]*#' "$script" \
	| grep -qP '\b(comm|join)\b.*\$\{?'"$var"'\}?|\$\{?'"$var"'\}?.*\b(comm|join)\b'
}

# ------------------------------------------------------------------
# is_direct_sort_consumer VAR SCRIPT
#
# Return 0 (true) if SCRIPT has a line where sort is the first command
# (start-of-line, possibly with leading whitespace) and $VAR appears
# as a positional argument on that line — i.e., the committed baseline
# is fed directly to sort, not via a preceding pipeline stage that
# transforms its content (sed, grep, awk, ...).
#
# This distinguishes:
#   sort "$MYBASE" > "$tmp/sorted"          ← direct sort (yes)
#   sed '...' "$MYBASE" | sort > "$tmp"     ← pipeline sort (no)
# ------------------------------------------------------------------
is_direct_sort_consumer() {
	local var="$1" script="$2"
	grep -v '^[[:space:]]*#' "$script" \
	| grep -qP '^[[:space:]]*sort[[:space:]].*\$\{?'"$var"'\}?'
}

# ------------------------------------------------------------------
# Selftest: three synthetic fixtures must each cause a FAIL exit.
#
# Fixture A — LC_ALL=C alone (no in-script sort of the baseline).
# Fixture B — proximity false-positive: unrelated sort within 6 lines
#             of a baseline assignment, but comm uses the raw baseline.
# Fixture C — naming-convention miss: var is named $BASE2 (no
#             "baseline" in the name) but points to a check-static path.
# ------------------------------------------------------------------
if [ "${1:-}" = "--selftest" ]; then
	gate="$(realpath "${BASH_SOURCE[0]}")"

	# Each fixture is placed under scripts/check-static/ inside an isolated
	# temp root so the gate's consumer scan finds exactly one script per run.
	# A dummy x.baseline is created at the expected path so consumer detection
	# does not abort before the safety check fires.
	#
	# run_fixture LABEL FIXTURE_FILE: copy FIXTURE_FILE into a fresh isolated
	# repo root and assert that the gate exits non-zero (fixture is caught).
	run_fixture() {
		local label="$1" src="$2" rc
		local tmproot
		tmproot="$(mktemp -d)"
		mkdir -p "$tmproot/scripts/check-static"
		cp "$src" "$tmproot/scripts/check-static/$(basename "$src")"
		touch "$tmproot/scripts/check-static/x.baseline"
		rc=0
		REPO_ROOT="$tmproot" bash "$gate" >/dev/null 2>&1 || rc=$?
		rm -rf "$tmproot"
		if [ "$rc" -eq 0 ]; then
			echo "SELFTEST FAIL: $label: gate returned 0 (expected non-zero)" >&2
			return 1
		fi
		echo "SELFTEST PASS: $label: gate correctly exits $rc" >&2
	}

	# Write fixture scripts to a shared temp dir; run each through run_fixture.
	stdir="$(mktemp -d)"
	trap 'rm -rf "$stdir"' EXIT

	# Fixture A: export LC_ALL=C present, but raw committed baseline to comm.
	# The old gate accepted LC_ALL=C as sufficient; the updated gate must FAIL.
	cat > "$stdir/fixture-a.sh" << 'FIXA'
#!/bin/bash
export LC_ALL=C
ROOT="${REPO_ROOT:-$(pwd)}"
MYBASE="$ROOT/scripts/check-static/x.baseline"
tmp="$(mktemp)"
some_producer > "$tmp"
comm -13 "$MYBASE" "$tmp"   # raw committed baseline -- unsafe even with LC_ALL=C
rm -f "$tmp"
FIXA

	# Fixture B: unrelated sort within 6 lines of baseline assignment, but
	# comm still uses the raw baseline (proximity heuristic false-positive trap).
	cat > "$stdir/fixture-b.sh" << 'FIXB'
#!/bin/bash
ROOT="${REPO_ROOT:-$(pwd)}"
MYBASE="$ROOT/scripts/check-static/x.baseline"
other_list="$(mktemp)"
some_producer > "$other_list"
sort "$other_list" > /dev/null   # unrelated sort within 6 lines of MYBASE=
tmp="$(mktemp)"
some_producer2 > "$tmp"
comm -13 "$MYBASE" "$tmp"       # raw baseline -- proximity sort gave false confidence
rm -f "$other_list" "$tmp"
FIXB

	# Fixture C: variable named $BASE2 (no "baseline" in the name) points to
	# a check-static path -- naming-convention detector would miss it.
	cat > "$stdir/fixture-c.sh" << 'FIXC'
#!/bin/bash
ROOT="${REPO_ROOT:-$(pwd)}"
BASE2="$ROOT/scripts/check-static/x.baseline"
tmp="$(mktemp)"
some_producer > "$tmp"
comm -13 "$BASE2" "$tmp"        # raw committed baseline, oddly-named variable
rm -f "$tmp"
FIXC

	self_fail=0
	run_fixture "fixture-A (LC_ALL=C alone)"          "$stdir/fixture-a.sh" || self_fail=1
	run_fixture "fixture-B (proximity false-positive)" "$stdir/fixture-b.sh" || self_fail=1
	run_fixture "fixture-C (naming-convention miss)"   "$stdir/fixture-c.sh" || self_fail=1

	if [ "$self_fail" -ne 0 ]; then
		echo "FAIL: $NAME: selftest: one or more fixtures were not caught" >&2
		exit 1
	fi
	echo "PASS: $NAME: selftest: all fixtures correctly detected"
	exit 0
fi

# ------------------------------------------------------------------
# Step 1: enumerate consumer scripts.
#
# A consumer is any .sh file in $CSDIR (excluding this script) where:
#   (a) a non-comment line assigns a variable to a path of the form
#       $ROOT/scripts/check-static/*.{baseline,txt}, AND
#   (b) the script contains at least one comm or join invocation on a
#       non-comment line.
#
# This is provenance-based detection: the variable name on the
# comm/join line does not need to contain "baseline".  A consumer
# using `comm -13 "$BASE2" ...` where BASE2 holds a check-static path
# is correctly detected.
# ------------------------------------------------------------------
mapfile -t consumer_scripts < <(
	for f in "$CSDIR"/*.sh; do
		[ -f "$f" ] || continue
		[ "$(realpath "$f")" = "$(realpath "${BASH_SOURCE[0]}")" ] && continue
		# Must have a var assigned to a check-static baseline path.
		mapfile -t bvars < <(extract_baseline_vars "$f")
		[ "${#bvars[@]}" -eq 0 ] && continue
		# Must have a comm or join call on a non-comment line.
		# Require trailing whitespace to exclude Python str.join() /
		# os.path.join() calls inside embedded heredocs.
		grep -v '^[[:space:]]*#' "$f" | grep -qP '\b(comm|join)\b[[:space:]]' || continue
		echo "$f"
	done | sort -u
)

if [ "${#consumer_scripts[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no comm/join consumers with check-static baseline references found" \
	     "in scripts/check-static/ — filter is broken?" >&2
	exit 1
fi

{
	echo "  $NAME: comm/join consumers with check-static baseline refs (${#consumer_scripts[@]}):"
	for cs in "${consumer_scripts[@]}"; do
		echo "    $(basename "$cs")"
	done
} >&2

# ------------------------------------------------------------------
# Step 2: safety check and (for direct-sort consumers) baseline validation.
# ------------------------------------------------------------------

checked=0

for script in "${consumer_scripts[@]}"; do
	sname="$(basename "$script" .sh)"

	# Collect baseline variable names for this consumer.
	mapfile -t bvars < <(extract_baseline_vars "$script")

	# ---- Safety check (operand tracking) ----
	#
	# For each committed baseline variable, check that it does NOT appear
	# as a direct operand to comm/join.  The committed file must always be
	# routed through an in-script sort before reaching comm/join.
	#
	# NOTE: export LC_ALL=C is NOT accepted as a substitute.  LC_ALL=C
	# pins the locale for sorts the script performs at runtime; it cannot
	# retroactively sort a committed file.  A script that pins LC_ALL=C
	# but passes the committed baseline raw to comm will still produce
	# wrong results on a host where the baseline was written in a
	# different locale.  Both conditions — in-script sort AND LC_ALL=C —
	# are desirable, but only the sort step is mandatory for correctness.
	consumer_safe=1
	for bv in "${bvars[@]}"; do
		if has_direct_comm "$bv" "$script"; then
			fail "  $NAME: '$sname' passes the committed baseline variable" \
			     "\$$bv directly to comm/join without an in-script sort."
			fail "  $NAME: LC_ALL=C alone does not fix this: it pins the" \
			     "runtime sort locale but cannot sort a committed file." \
			     "Fix: sort \"\$$bv\" > \"\$tmp/sorted\" and use \$tmp/sorted in comm."
			consumer_safe=0
		fi
	done

	if [ "$consumer_safe" -eq 0 ]; then
		continue
	fi

	# ---- Baseline C-sort validation (direct-sort consumers only) ----
	#
	# If the consumer sorts the committed baseline variable directly
	# (sort is the first command on the line, taking the baseline var as
	# a positional argument — not inside a pipeline that transforms the
	# content first), the committed file must be byte-identical to its
	# LC_ALL=C sort output.
	#
	# Baselines consumed through comment-stripping pipelines (sed/awk
	# before sort) carry intentional section comments that make the raw
	# file non-C-sorted by design; those are excluded.
	is_direct_sort=0
	for bv in "${bvars[@]}"; do
		if is_direct_sort_consumer "$bv" "$script"; then
			is_direct_sort=1
			break
		fi
	done

	if [ "$is_direct_sort" -eq 0 ]; then
		echo "  $NAME: OK  $sname (pipeline-sort consumer; committed baseline order not checked)" >&2
		continue
	fi

	# Direct-sort consumer: validate every committed baseline path.
	mapfile -t bpaths < <(
		grep -v '^[[:space:]]*#' "$script" \
		| grep -oP '\$\{?ROOT\}?/scripts/check-static/[^"'"'"'[:space:]]+\.(?:baseline|txt)' \
		| sed 's/\${ROOT}/\$ROOT/g' \
		| sort -u
	)

	if [ "${#bpaths[@]}" -eq 0 ]; then
		fail "  $NAME: '$sname' is a direct-sort consumer but no" \
		     "\$ROOT/scripts/check-static/*.{baseline,txt} path was found" \
		     "in the script — update the extraction regex."
		continue
	fi

	for bpath in "${bpaths[@]}"; do
		real="${bpath/\$ROOT/$ROOT}"

		if [ ! -f "$real" ]; then
			fail "  $NAME: '$sname': baseline not found: $real"
			continue
		fi

		bname="$(basename "$real")"
		sorted="$(LC_ALL=C sort "$real")"
		actual="$(cat "$real")"

		checked=$((checked + 1))

		if [ "$sorted" != "$actual" ]; then
			fail "  $NAME: $bname is NOT byte-identical to \`LC_ALL=C sort\`"
			fail "  $NAME: '$sname' passes this file directly to sort before comm;" \
			     "a locale mismatch means comm silently degrades on non-C-locale hosts."
			fail "  $NAME: fix: LC_ALL=C sort -o '$real' '$real'"
		else
			echo "  $NAME: OK  $bname (C-sorted, direct-sort consumer: $sname)" >&2
		fi
	done
done

if [ "$_fail" -ne 0 ]; then
	echo "FAIL: $NAME: collation safety or baseline C-sort invariant violated"
	exit 1
fi

if [ "$checked" -eq 0 ]; then
	echo "PASS: $NAME (${#consumer_scripts[@]} consumer(s) safe;" \
	     "no direct-sort baselines to validate)"
else
	echo "PASS: $NAME ($checked direct-sort baseline(s) verified C-sorted," \
	     "${#consumer_scripts[@]} consumer(s))"
fi
exit 0
