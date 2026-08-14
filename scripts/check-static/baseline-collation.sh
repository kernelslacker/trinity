#!/bin/bash
#
# baseline-collation: assert that every committed baseline file whose
# consuming script invokes comm(1) against a directly-sorted copy of
# that file is byte-identical to its own LC_ALL=C sort output.
#
# Background
# ----------
# comm(1) requires both inputs to be sorted under the *same* locale.
# When a committed baseline was originally sorted under en_US.UTF-8 but
# the gate runs in a C/POSIX shell (CI containers, cron, env-scrubbed
# runners), sort produces a different order, comm silently degrades, and
# set-difference results are wrong.  c481a1c1f5a7 ("dead-arm-detect: pin
# LC_ALL=C so comm runs in consistent collation") fixed one such gate.
# This check prevents the class from recurring: any gate that directly
# sorts a committed baseline and feeds the result to comm must keep its
# baseline in LC_ALL=C order so the invariant is checkable without
# running the gate itself.
#
# Consumer detection
# ------------------
# A "direct sort" consumer is a script that contains BOTH:
#   (a) a comm invocation (anywhere in the file), AND
#   (b) a line matching:  ^<whitespace?>sort <whitespace>"...$<Var>aseline<Var>..."
#       i.e. sort is called as a standalone command with a baseline
#       variable as its direct argument — not as the endpoint of a
#       sed/awk/grep pipeline (which strips/transforms the content
#       first and is therefore not order-sensitive in the same way).
#
# Fail-close
# ----------
# If the consumer list is empty the filter is almost certainly broken
# (the known consumer dead-arm-detect.sh vanished or was restructured).
# Gate fails rather than silently passing with zero checks performed.
#
# Scope
# -----
# Only baselines used by direct-sort comm consumers are checked.  Baselines
# consumed by other patterns (comment-stripped pipelines, grep-only readers)
# are deliberately excluded: they are not order-sensitive and several carry
# intentional section comments that make the file non-C-sorted by design.

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
# ------------------------------------------------------------------

mapfile -t consumer_scripts < <(
	grep -rl '^[[:space:]]*sort[[:space:]]\+".*\$.*aseline' \
		"$CSDIR"/*.sh 2>/dev/null | \
	while IFS= read -r f; do
		grep -ql '\bcomm\b' "$f" && echo "$f"
	done | sort -u
)

if [ "${#consumer_scripts[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no comm/join consumers of directly-sorted committed" \
	     "baselines found — filter is broken?" >&2
	exit 1
fi

# Emit the consumer list so the population is auditable on every run.
{
	echo "  $NAME: order-sensitive comm consumers (${#consumer_scripts[@]}):"
	for cs in "${consumer_scripts[@]}"; do
		echo "    $(basename "$cs")"
	done
} >&2

# ------------------------------------------------------------------
# Step 2: for each consumer, extract and validate its baseline(s).
# ------------------------------------------------------------------

checked=0

for script in "${consumer_scripts[@]}"; do
	sname="$(basename "$script" .sh)"

	# Extract committed baseline paths referenced from the script.
	# Match the literal string $ROOT/scripts/check-static/<file> in the
	# source; that is the canonical form all consumer scripts use.
	mapfile -t bpaths < <(
		grep -oP '\$ROOT/scripts/check-static/[^"'\''[:space:]]+' "$script" \
		| grep -E '\.(baseline|txt)$' \
		| sort -u
	)

	if [ "${#bpaths[@]}" -eq 0 ]; then
		fail "  $NAME: consumer '$sname' matched the sort-baseline pattern" \
		     "but no \$ROOT/scripts/check-static/*.{baseline,txt} path was found" \
		     "in the script — update the extraction regex."
		continue
	fi

	for bpath in "${bpaths[@]}"; do
		real="${bpath/\$ROOT/$ROOT}"

		if [ ! -f "$real" ]; then
			fail "  $NAME: consumer '$sname': baseline not found: $real"
			continue
		fi

		bname="$(basename "$real")"
		sorted="$(LC_ALL=C sort "$real")"
		actual="$(cat "$real")"

		checked=$((checked + 1))

		if [ "$sorted" != "$actual" ]; then
			fail "  $NAME: $bname is NOT byte-identical to \`LC_ALL=C sort\`"
			fail "  $NAME: consumer '$sname' sorts this file before comm; a" \
			     "locale mismatch means comm silently degrades on non-UTF-8 hosts."
			fail "  $NAME: fix: LC_ALL=C sort -o '$real' '$real'"
		else
			echo "  $NAME: OK  $bname (C-sorted, used by $sname)" >&2
		fi
	done
done

if [ "$checked" -eq 0 ]; then
	echo "FAIL: $NAME: consumer scripts found but no baseline files were checked" \
	     "(extraction broken?)" >&2
	exit 1
fi

if [ "$_fail" -ne 0 ]; then
	echo "FAIL: $NAME: one or more committed baselines are not LC_ALL=C sorted"
	exit 1
fi

echo "PASS: $NAME ($checked baseline(s) verified C-sorted, ${#consumer_scripts[@]} consumer(s))"
exit 0
