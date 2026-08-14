#!/bin/bash
#
# baseline-collation: assert that every committed baseline file used by
# a comm(1)/join(1) consumer script is either byte-identical to its own
# LC_ALL=C sort output (for direct-sort consumers), or that the consumer
# protects against collation divergence via export LC_ALL=C or an
# in-script re-sort.
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
# Consumer detection
# ------------------
# A "collation-sensitive consumer" is a script where at least one
# non-comment line contains BOTH a comm(1) or join(1) invocation AND a
# reference to a variable whose name contains "baseline" (case-insensitive),
# e.g.:
#
#   comm -13 "$BASELINE" "$tmp"          ← dangerous: committed file direct to comm
#   comm -13 "$tmp/baseline_sorted" ...  ← variable path contains "baseline"
#   comm -23 "$current_tmp" "$baseline_tmp"  ← variable name contains "baseline"
#
# Keying on the comm/join call line (not on a sort line) closes several
# holes in the original detector:
#
#  Hole 1 — case-sensitivity: the old grep used a lowercase-only pattern
#    (.*\$.*aseline) which matched "baseline_file" but not "BASELINE".
#    Any script using the house-style uppercase variable was invisible.
#
#  Hole 2 — unanchored regex: .*\$.*aseline spans the entire line, so
#    `sort "$warn_list" > "$baseline_file"` matched even though sort's
#    direct argument was the temp file, not the committed baseline.
#
#  Hole 3 — sort-line requirement inverted the risk: the most dangerous
#    shape — `comm -13 "$COMMITTED_BASELINE" "$tmp"` with no sort — was
#    NEVER selected because there was no matching sort line.
#
# Acceptance note: a script containing
#   comm -13 "$BASELINE" "$tmp"
# with an uppercase BASELINE variable and no in-script sort would be
# detected as a consumer (comm on same line as "baseline") and would then
# fail the safety check (no export LC_ALL=C, no sort near the baseline
# reference), causing a gate failure.
#
# Safety check
# ------------
# For each detected consumer we verify EITHER:
#   • the script contains `export LC_ALL=C`, OR
#   • the script re-sorts the committed baseline operand in-script:
#     detected when a sort command appears within 6 lines after a line
#     referencing any "baseline"-named variable (case-insensitive).
#     This catches both single-line (`sort "$BASELINE" > tmp`) and
#     multi-line pipeline forms (`sed ... "$BASELINE" \n | sort > tmp`).
#
# Baseline C-sort validation
# --------------------------
# For direct-sort consumers (sort takes the committed baseline variable as
# a positional argument, not via a comment-stripping pipeline), the
# committed baseline must be byte-identical to its own LC_ALL=C sort
# output.  This is necessary because:
#   • the committed file content is passed to sort unchanged, so
#   • the committed order must equal LC_ALL=C order to be locale-invariant.
#
# Baselines consumed through comment-stripping pipelines (sed/awk before
# sort) carry intentional section comments that make the file non-C-sorted
# by design.  Those are explicitly excluded: the strip→sort sequence is
# always locale-independent regardless of the committed file's raw order.
#
# Fail-close
# ----------
# If the consumer list is empty the filter is almost certainly broken
# (the known consumer dead-arm-detect.sh vanished or was restructured).
# Gate fails rather than silently passing with zero checks performed.

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
# Step 1: enumerate consumer scripts.
#
# A consumer is any .sh file in $CSDIR where at least one non-comment
# line contains BOTH a comm/join invocation AND "baseline" (case-insensitive).
# Matching on the same line means:
#   • Python ".join()" in inline heredocs never matches (no "baseline" on
#     the same line).
#   • `comm <(printf ...) <(printf ...)` never matches unless the printf
#     args happen to contain "baseline" — which, by convention, they do not.
#   • `comm "$tmp/baseline_sorted" ...` does match, correctly.
#
# We skip the checker itself to avoid matching the acceptance-note examples
# embedded in our own comments.
# ------------------------------------------------------------------

mapfile -t consumer_scripts < <(
	for f in "$CSDIR"/*.sh; do
		[ -f "$f" ] || continue
		# Skip ourselves — our own comments contain the example patterns.
		[ "$(realpath "$f")" = "$(realpath "${BASH_SOURCE[0]}")" ] && continue
		# Non-comment line must contain comm/join AND "baseline" (case-insensitive)
		grep -iqE '^[^#]*\b(comm|join)\b[^#]*[Bb][Aa][Ss][Ee][Ll][Ii][Nn][Ee]' "$f" || continue
		echo "$f"
	done | sort -u
)

if [ "${#consumer_scripts[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no comm/join consumers with baseline references found" \
	     "in scripts/check-static/ — filter is broken?" >&2
	exit 1
fi

# Emit the consumer list so the population is auditable on every run.
{
	echo "  $NAME: comm/join consumers with baseline refs (${#consumer_scripts[@]}):"
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

	# ---- Safety check ----
	#
	# The consumer must either:
	#   (a) export LC_ALL=C as a standalone command (not a single-command
	#       prefix like `LC_ALL=C sort`), which pins the locale for the
	#       entire script, OR
	#   (b) re-sort the committed baseline operand in-script.
	#
	# Re-sort detection (awk, case-insensitive): flag if a sort command
	# appears within 6 lines after a line referencing any variable whose
	# name contains "baseline".  6 lines covers typical multi-line pipelines
	# with backslash continuation (sed → grep → sort).  Sort is matched
	# without \b (not supported in awk ERE) using a character-class anchor:
	# (^|non-alnum-non-_)sort(space|pipe|end).
	has_lc_all=0
	grep -qE '^[[:space:]]*export[[:space:]]+LC_ALL=C([[:space:]]|$)' \
		"$script" && has_lc_all=1

	has_resort=0
	if awk '
		BEGIN { baseline_line = 0 }
		tolower($0) ~ /baseline/ { baseline_line = NR }
		/(^|[^[:alnum:]_])sort([[:space:]]|$|\|)/ {
			if (baseline_line > 0 && (NR - baseline_line) <= 6) found = 1
		}
		END { exit !found }
	' "$script"; then
		has_resort=1
	fi

	if [ "$has_lc_all" -eq 0 ] && [ "$has_resort" -eq 0 ]; then
		fail "  $NAME: '$sname' invokes comm/join with a baseline-named variable" \
		     "but has neither 'export LC_ALL=C' nor an in-script sort of the" \
		     "baseline operand — collation mismatch risk on non-C-locale hosts."
		fail "  $NAME: fix: add 'export LC_ALL=C' near the top of the script, or" \
		     "sort the committed baseline variable before using its content in comm/join."
		continue
	fi

	# ---- Baseline C-sort validation (direct-sort consumers only) ----
	#
	# If the consumer directly sorts the committed baseline variable (sort
	# has the baseline-named variable as a positional argument, not as the
	# output of a sed/grep pipeline), the committed file must be
	# byte-identical to its own LC_ALL=C sort output.
	#
	# Detect: any line matching
	#   ^<ws>sort<ws>...$<Variable_Containing_Baseline>...
	# where the variable name (case-insensitive) contains "baseline".
	# This matches `sort "$baseline_file" > tmp` but NOT
	# `sed ... "$BASELINE" | sort` (sort has no baseline-named arg).
	is_direct_sort=0
	grep -iqE \
		'^[[:space:]]*(sort)[[:space:]].*\$[{]?[A-Za-z_]*[Bb][Aa][Ss][Ee][Ll][Ii][Nn][Ee][A-Za-z_]*[}]?' \
		"$script" && is_direct_sort=1

	if [ "$is_direct_sort" -eq 0 ]; then
		# Pipeline-sort or LC_ALL=C-protected consumer: the committed
		# baseline is comment-stripped or otherwise transformed before
		# sorting, so the committed file's raw order is irrelevant.
		# No baseline C-sort check needed.
		echo "  $NAME: OK  $sname (pipeline-sort or LC_ALL=C; baseline order not checked)" >&2
		continue
	fi

	# Direct-sort consumer: validate every committed baseline path.
	mapfile -t bpaths < <(
		grep -oP '\$ROOT/scripts/check-static/[^"'\''[:space:]]+' "$script" \
		| grep -E '\.(baseline|txt)$' \
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
	echo "PASS: $NAME (${#consumer_scripts[@]} consumer(s) safe via LC_ALL=C or pipeline-sort;" \
	     "no direct-sort baselines to validate)"
else
	echo "PASS: $NAME ($checked direct-sort baseline(s) verified C-sorted," \
	     "${#consumer_scripts[@]} consumer(s))"
fi
exit 0
