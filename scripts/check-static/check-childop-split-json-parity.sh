#!/bin/bash
#
# check-childop-split-json-parity.sh -- structural parity gate between the
# childop-split TEXT surface and the childop_split_json: JSON object in the
# same periodic dump.
#
# Background: childop_split_dump() emits two parallel streams in the same
# stats-log flush:
#
#   TEXT: childop_split:   walltime/syscalls/iterations rendered as human-%
#         childop_X:       supplemental scalar counters (e.g. direct_tally_dropped)
#
#   JSON: childop_split_json:  {walltime_ns:{...}, syscalls:{...},
#                               iterations:{...}, X:N, ...}
#
# The two surfaces must remain in sync.  In the past, adding a text counter
# without a matching JSON field (or vice versa) has silently forked the two
# surfaces on at least four occasions.  This gate prevents that by asserting
# parity at the schema level: every supplemental scalar counter present on the
# text side must have a corresponding top-level key in the JSON object, and
# every top-level JSON key that is not one of the three "core split" fields
# (walltime_ns, syscalls, iterations -- which are rendered as a single line on
# the text side) must have a matching text-side counter.
#
# The check is driven from periodic-text-schema.baseline, which is already
# generated from the source by check-periodic-text-schema.sh.  Driving from
# the compiled baseline means this gate does not need to re-parse C source;
# it fails only when the baseline itself drifts (i.e. after the code is
# changed but before both surfaces are updated).
#
# Fail-close on an empty key set: if the extractor produces no JSON keys or
# no text counters the gate fails immediately rather than silently passing.
#
# To verify: run after any change to stats/periodic/childop-split.c and
# after regenerating scripts/check-static/periodic-text-schema.baseline.

set -u

NAME="childop-split-json-parity"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE="$ROOT/scripts/check-static/periodic-text-schema.baseline"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$BASELINE" ] || fail "baseline not found: ${BASELINE#"$ROOT"/} -- run check-periodic-text-schema.sh --regen first"

# ---------------------------------------------------------------------------
# Extract the === childop-split === section from the baseline.
# ---------------------------------------------------------------------------

section=$(awk '
	/^=== childop-split ===/ { found=1; next }
	found && /^===/ { exit }
	found { print }
' "$BASELINE")

[ -n "$section" ] || fail "=== childop-split === section not found in ${BASELINE#"$ROOT"/}"

# ---------------------------------------------------------------------------
# JSON side: extract top-level keys from the childop_split_json: line.
#
# The schema template looks like:
#   childop_split_json: {walltime_ns:{childop:,...},syscalls:{...},iterations:{...},direct_tally_dropped:}
#
# Top-level keys are those that appear directly inside the outer { ... }
# object -- i.e., keys followed by ":{" (nested object) or ":" at depth 0.
# The awk below walks character-by-character, tracking brace depth, and
# records each key encountered at depth 1 (direct child of the outer {}).
# ---------------------------------------------------------------------------

json_line=$(printf '%s\n' "$section" | grep '^childop_split_json:')
[ -n "$json_line" ] || fail "childop_split_json: line absent from childop-split baseline section"

json_toplevel=$(printf '%s\n' "$json_line" | awk '
BEGIN { depth=0; key="" }
{
	# Locate the opening { that starts the JSON object.
	start = index($0, "{")
	if (start == 0) next
	s = substr($0, start)
	n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "{") {
			depth++
		} else if (c == "}") {
			depth--
		} else if (depth == 1) {
			# At top-level depth: accumulate characters for a key name.
			if (c == ":") {
				if (length(key) > 0) {
					print key
					key = ""
				}
			} else if (c ~ /[a-zA-Z0-9_]/) {
				key = key c
			} else {
				# Non-identifier character resets in-progress key.
				if (length(key) > 0 && c != ",") key = ""
				# Comma at top-level is just a separator -- ignore.
			}
		} else {
			key = ""
		}
	}
}
' | LC_ALL=C sort -u)

[ -n "$json_toplevel" ] || fail "no top-level JSON keys extracted from childop_split_json: line -- extractor stale"

# ---------------------------------------------------------------------------
# Text side: extract supplemental counter names.
#
# These are lines in the childop-split section that are neither the main
# childop_split: line (which renders walltime/syscalls/iterations as
# human-readable percentages) nor the childop_split_json: line (the JSON
# template itself).  Lines like:
#
#   childop_direct_tally_dropped:
#
# give us the base name "direct_tally_dropped" by stripping the leading
# "childop_" prefix and the trailing ":".
# ---------------------------------------------------------------------------

text_counters=$(printf '%s\n' "$section" \
	| grep -v '^childop_split:' \
	| grep -v '^childop_split_json:' \
	| grep -E '^childop_[a-z_][a-z0-9_]*:' \
	| sed 's/^childop_//; s/:[[:space:]]*//' \
	| LC_ALL=C sort -u)

[ -n "$text_counters" ] || fail "no supplemental text counters found in childop-split section -- extractor stale or all text-only counters removed without clearing this gate"

# ---------------------------------------------------------------------------
# The three "core split" fields are rendered as a single childop_split: line
# on the text side, not as individual named counters.  They are exempt from
# the requirement that every JSON top-level key have a text-side counter.
# ---------------------------------------------------------------------------

CORE_SPLIT_FIELDS="walltime_ns
syscalls
iterations"

# ---------------------------------------------------------------------------
# Parity check 1: every supplemental text counter must appear as a top-level
# JSON key.
# ---------------------------------------------------------------------------

errors=()
while IFS= read -r tctr; do
	if ! printf '%s\n' "$json_toplevel" | grep -qx "$tctr"; then
		errors+=("text counter 'childop_${tctr}:' has no matching top-level JSON key '${tctr}' in childop_split_json:")
	fi
done < <(printf '%s\n' "$text_counters")

# ---------------------------------------------------------------------------
# Parity check 2: every non-core top-level JSON key must have a matching
# supplemental text counter.
# ---------------------------------------------------------------------------

while IFS= read -r jkey; do
	if printf '%s\n' "$CORE_SPLIT_FIELDS" | grep -qx "$jkey"; then
		continue   # core split field: represented by childop_split: line
	fi
	if ! printf '%s\n' "$text_counters" | grep -qx "$jkey"; then
		errors+=("JSON key '${jkey}' in childop_split_json: has no matching text-side counter 'childop_${jkey}:'")
	fi
done < <(printf '%s\n' "$json_toplevel")

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------

if [ "${#errors[@]}" -gt 0 ]; then
	for e in "${errors[@]}"; do
		echo "FAIL: $NAME: $e" >&2
	done
	echo "FAIL: $NAME: ${#errors[@]} parity violation(s)" \
	     "-- add the missing field to both surfaces, then regen periodic-text-schema.baseline" >&2
	exit 1
fi

n_json=$(printf '%s\n' "$json_toplevel" | wc -l | tr -d ' ')
n_text=$(printf '%s\n' "$text_counters" | wc -l | tr -d ' ')
echo "PASS: $NAME: ${n_json} JSON top-level keys, ${n_text} supplemental text counter(s), surfaces in parity"
exit 0
