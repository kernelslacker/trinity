#!/bin/bash
#
# stats-json-schema: pin the set of JSON keys the --stats-json dumper
# emits from inline printf format strings in stats/json/*.c against a
# golden baseline.
#
# Background: dump_stats_json() and its section emitters print a
# hand-authored JSON document.  Downstream consumers (scrapers,
# dashboards, the periodic-text schema audit) key off top-level
# section wrappers ("kcov", "fault_injection", "corruption", ...)
# and off scalar counter keys within each section ("op_count",
# "total_pcs", "returned_enomem", ...).  A rename, removal, or
# accidental typo silently reshapes the JSON with no compile or test
# failure -- consumers just start reading NULL for the renamed key.
#
# This check makes drift structural: extract every JSON key literal
# from the inline printf format strings under stats/json/*.c and diff
# the sorted-unique list against a baseline.  A new key trips the
# check with a diff pointing at the drift; the fix is to inspect the
# change, decide whether the schema change is intentional, and either
# revert the code or update the baseline in the SAME commit that
# ships the schema change.
#
# STAT_FIELD*/STAT_FIELD_JSON* table emissions are not pinned here.
# Those keys are structurally captured by their macro definition
# (name = #suffix or explicit json_key) and land in dedicated
# descriptor tables that check-stats-reachable already audits from
# the other direction.  This check pins the hand-authored inline
# format strings, which have no descriptor gate.
#
# To regenerate after an intentional schema change:
#   scripts/check-static/stats-json-schema.sh --regen
# then review the resulting stats-json-schema.baseline diff and
# commit it alongside the schema change.

set -u

NAME="stats-json-schema"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SRCDIR="$ROOT/stats/json"
BASELINE="$ROOT/scripts/check-static/stats-json-schema.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$SRCDIR" ] || fail "cannot read $SRCDIR"

# Extract every JSON key literal from inline format strings under
# stats/json/*.c.  The key is any C-escaped double-quoted lowercase
# identifier followed by ':' -- matches both scalar keys ("foo":%lu)
# and section-wrapper keys ("foo":{).  Whole-file globbing (not just
# dump.c) covers every section emitter.
keys=$(grep -Eoh '\\"[a-z_][a-z0-9_]*\\":' "$SRCDIR"/*.c 2>/dev/null \
	| sed -E 's/^\\"//; s/\\":$//' \
	| sort -u)

[ -n "$keys" ] || fail "no JSON key literals extracted from $SRCDIR -- key-extraction regex is stale"

# --regen: overwrite the baseline in place.  Only for after-intentional-
# change use; the normal check path never writes.
if [ "${1:-}" = "--regen" ]; then
	{
		cat <<'EOF'
# stats-json-schema.baseline
#
# Sorted-unique list of JSON key literals emitted from inline printf
# format strings in stats/json/*.c.  Regenerate with
#   scripts/check-static/stats-json-schema.sh --regen
# after an intentional schema change; commit the diff alongside the
# code change with a Summary line explaining why the key moved.
#
# Lines beginning with '#' and blank lines are ignored.
EOF
		printf '%s\n' "$keys"
	} > "$BASELINE"
	echo "REGEN: $NAME: wrote $(printf '%s\n' "$keys" | wc -l) keys to ${BASELINE#"$ROOT"/}"
	exit 0
fi

[ -r "$BASELINE" ] || fail "baseline missing at ${BASELINE#"$ROOT"/} -- run with --regen to seed"

baseline_keys=$(grep -Ev '^\s*(#|$)' "$BASELINE" | tr -d ' \t' | sort -u)

added=$(comm -23 <(printf '%s\n' "$keys") <(printf '%s\n' "$baseline_keys"))
removed=$(comm -13 <(printf '%s\n' "$keys") <(printf '%s\n' "$baseline_keys"))

if [ -n "$added" ] || [ -n "$removed" ]; then
	{
		echo "FAIL: $NAME: JSON schema drift vs baseline (${BASELINE#"$ROOT"/})"
		if [ -n "$added" ]; then
			echo "  added keys (not in baseline):"
			printf '    + %s\n' $added
		fi
		if [ -n "$removed" ]; then
			echo "  removed keys (in baseline but not in source):"
			printf '    - %s\n' $removed
		fi
		echo "  If the schema change is intentional, run"
		echo "    scripts/check-static/stats-json-schema.sh --regen"
		echo "  and commit the updated baseline alongside the code change."
	} >&2
	exit 1
fi

echo "PASS: $NAME: $(printf '%s\n' "$keys" | wc -l) JSON keys pinned"
exit 0
