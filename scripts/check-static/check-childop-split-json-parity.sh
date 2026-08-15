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
#         childop_X:       supplemental scalar counters
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
# Empty-set allowance: if both the supplemental text counter set and the
# non-core JSON key set are empty, the gate prints a notice and exits 0.
# This is the current expected state (zero supplemental counters).  The gate
# fires forward when the next counter is added to one surface without a
# matching entry on the other.  The old fail-close on an empty set is NOT
# used here; the empty-set state is explicitly permitted.
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
#   childop_split_json: {walltime_ns:{childop:,...},syscalls:{...},iterations:{...}}
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
				# Non-identifier character (including top-level comma) resets
				# any in-progress key.  A comma arrives after the value of the
				# preceding key:value pair; if the value was a scalar its
				# characters have accumulated into `key` and must be flushed
				# before the next key name starts.
				if (length(key) > 0) key = ""
			}
		} else {
			key = ""
		}
	}
}
' | LC_ALL=C sort -u)

# ---------------------------------------------------------------------------
# Fixture self-test: verify the awk key-extractor produces clean keys when
# there are two or more scalar key:value pairs at top-level depth.  Before
# the comma-bleed fix, the second key would be parsed as "<value1><key2>"
# because the value characters accumulated into `key` and the separating comma
# was exempted from the reset.  Exercise a synthetic JSON string that has
# two scalar keys (alpha, beta) plus the three core nested-object keys to
# catch any regression in one shot.
# ---------------------------------------------------------------------------

_fixture_json="dummy: {walltime_ns:{childop:0},syscalls:{childop:0},iterations:{childop:0},alpha:42,beta:7}"
_fixture_keys=$(printf '%s\n' "$_fixture_json" | awk '
BEGIN { depth=0; key="" }
{
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
			if (c == ":") {
				if (length(key) > 0) {
					print key
					key = ""
				}
			} else if (c ~ /[a-zA-Z0-9_]/) {
				key = key c
			} else {
				if (length(key) > 0) key = ""
			}
		} else {
			key = ""
		}
	}
}
' | LC_ALL=C sort -u)

for _want in alpha beta iterations syscalls walltime_ns; do
	if ! printf '%s\n' "$_fixture_keys" | grep -qx "$_want"; then
		fail "awk key-extractor fixture: expected key '${_want}' not found in output (got: $(printf '%s' "$_fixture_keys" | tr '\n' ' ')) -- comma-bleed regression?"
	fi
done
unset _fixture_json _fixture_keys _want

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

# ---------------------------------------------------------------------------
# The three "core split" fields are rendered as a single childop_split: line
# on the text side, not as individual named counters.  They are exempt from
# the requirement that every JSON top-level key have a text-side counter.
# ---------------------------------------------------------------------------

CORE_SPLIT_FIELDS="walltime_ns
syscalls
iterations"

# ---------------------------------------------------------------------------
# Positive assertion 1: all three core split fields must be present as
# top-level keys in childop_split_json:.  Being "exempt from parity" means
# they need no matching supplemental text counter — it does NOT mean they
# may be absent from the JSON object.  A regression that drops one of these
# keys would otherwise pass the parity checks undetected.
# ---------------------------------------------------------------------------

while IFS= read -r _cfield; do
	[ -z "$_cfield" ] && continue
	if ! printf '%s\n' "$json_toplevel" | grep -qx "$_cfield"; then
		fail "core field '${_cfield}' absent from childop_split_json: — JSON lost a required core split key"
	fi
done < <(printf '%s\n' "$CORE_SPLIT_FIELDS")

# ---------------------------------------------------------------------------
# Positive assertion 2: childop_split: must be present on the text side.
# This single line encodes walltime_ns/syscalls/iterations as a human-
# readable token; its absence means the core fields have dropped from the
# text surface entirely.
# ---------------------------------------------------------------------------

printf '%s\n' "$section" | grep -q '^childop_split:' || \
	fail "childop_split: line absent from childop-split baseline section — core fields lost from text surface"

# ---------------------------------------------------------------------------
# Selftest for positive assertion 1: verify the loop detects a missing core
# field.  Use a fixture that omits 'iterations' and confirm it is caught.
# ---------------------------------------------------------------------------

_st_keys="walltime_ns
syscalls"
_st_caught=""
while IFS= read -r _cfield; do
	[ -z "$_cfield" ] && continue
	if ! printf '%s\n' "$_st_keys" | grep -qx "$_cfield"; then
		_st_caught="$_cfield"
		break
	fi
done < <(printf '%s\n' "$CORE_SPLIT_FIELDS")
[ "$_st_caught" = "iterations" ] || \
	fail "selftest: core-field absence check: expected 'iterations' missing, got '${_st_caught:-none}'"
unset _st_keys _st_caught _cfield

# ---------------------------------------------------------------------------
# Selftest for positive assertion 2: a section that lacks childop_split:
# must not produce a false pass.  Verify grep correctly returns non-zero.
# ---------------------------------------------------------------------------

_st_section="childop_split_json: {walltime_ns:{},syscalls:{},iterations:{}}"
printf '%s\n' "$_st_section" | grep -q '^childop_split:' && \
	fail "selftest: childop_split: wrongly detected in fixture that lacks it"
unset _st_section

# Compute non-core JSON keys (those not in CORE_SPLIT_FIELDS).
json_noncorekeys=$(printf '%s\n' "$json_toplevel" | while IFS= read -r jkey; do
	if ! printf '%s\n' "$CORE_SPLIT_FIELDS" | grep -qx "$jkey"; then
		printf '%s\n' "$jkey"
	fi
done)

# ---------------------------------------------------------------------------
# Empty-set allowance: if both supplemental text counters and non-core JSON
# keys are absent, the gate passes with a notice.  This is the current
# expected state after the last supplemental counter was removed.  The gate
# remains installed as forward-only protection: when the next counter lands
# without a matching entry on the other surface, the parity checks below
# will fire.
# ---------------------------------------------------------------------------

if [ -z "$text_counters" ] && [ -z "$json_noncorekeys" ]; then
	echo "check-childop-split-json-parity: zero supplemental counters — empty-set allowance"
	exit 0
fi

# If exactly one side is empty, that is already a parity violation -- fall
# through to the parity checks, which will report the mismatch.

# ---------------------------------------------------------------------------
# Parity check 1: every supplemental text counter must appear as a top-level
# JSON key.
# ---------------------------------------------------------------------------

errors=()
while IFS= read -r tctr; do
	[ -z "$tctr" ] && continue
	if ! printf '%s\n' "$json_toplevel" | grep -qx "$tctr"; then
		errors+=("text counter 'childop_${tctr}:' has no matching top-level JSON key '${tctr}' in childop_split_json:")
	fi
done < <(printf '%s\n' "$text_counters")

# ---------------------------------------------------------------------------
# Parity check 2: every non-core top-level JSON key must have a matching
# supplemental text counter.
# ---------------------------------------------------------------------------

while IFS= read -r jkey; do
	[ -z "$jkey" ] && continue
	if ! printf '%s\n' "$text_counters" | grep -qx "$jkey"; then
		errors+=("JSON key '${jkey}' in childop_split_json: has no matching text-side counter 'childop_${jkey}:'")
	fi
done < <(printf '%s\n' "$json_noncorekeys")

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

n_json=$(printf '%s\n' "$json_noncorekeys" | grep -c . || true)
n_text=$(printf '%s\n' "$text_counters" | grep -c . || true)
echo "PASS: $NAME: ${n_json} non-core JSON key(s), ${n_text} supplemental text counter(s), surfaces in parity"
exit 0
