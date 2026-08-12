#!/bin/bash
#
# uapi-shim-values: verify that trinity's uapi-gap #define shims carry the
# correct numeric values for enum-backed UAPI constants.
#
# WHY THIS EXISTS: every shim of the form
#
#   #ifndef IFLA_GRE_LOCAL
#   #define IFLA_GRE_LOCAL  6
#   #endif
#
# is unconditionally taken: cpp #ifndef is always true for enum values
# because enums are not macros.  The shim is therefore not a fallback -- it
# IS the definition on every build.  A typo or miscounted enum position
# compiles clean, links clean, and silently encodes the wrong netlink
# attribute forever.
#
# The check parses trinity's shim #define lines and compares them against
# scripts/check-static/uapi-shim-values.baseline, which was verified against
# a pinned linux-linus sysroot.
#
# Families covered: IFLA_GRE_*, IFLA_IPTUN_*, NDA_*, XFRMA_* (newer attrs),
#                   NL80211_CMD_* (recently corrected subset)
# NOT YET covered (272 shims total -- follow-up task):
#   NFTA_*, CTA_*, TCA_*, ETHTOOL_A_*, MDBA_*, DCB_ATTR_*

set -u

NAME="uapi-shim-values"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/uapi-shim-values.baseline"

[ -f "$BASELINE" ] || { echo "PASS: $NAME (no baseline)"; exit 0; }

command -v perl >/dev/null 2>&1 || { echo "ERROR: $NAME: perl unavailable, cannot verify shim values"; exit 1; }

# Collect all trinity #define lines across the whole source tree after
# stripping C comments, so a commented-out stale value is not matched.
#
# Result format: one "SYMBOL VALUE" pair per line, for all defines that
# have a purely numeric value (decimal, no parens/expressions).
define_map=$(
	find "$ROOT" -path "$ROOT/scripts" -prune -o \
		\( -name '*.c' -o -name '*.h' \) -print 2>/dev/null \
	| sort \
	| xargs perl -0777 -pe \
		's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' \
		2>/dev/null \
	| grep -oE '#[[:space:]]*define[[:space:]]+[A-Z][A-Z0-9_]+[[:space:]]+[0-9]+([[:space:]]|$)' \
	| awk '{sub(/^#[[:space:]]*define[[:space:]]+/, ""); print $1, $2}'
)

fail=0
checked=0
missing=0

while IFS= read -r line; do
	# Strip inline comments and skip blank/comment lines.
	line="${line%%#*}"
	[[ -z "${line//[[:space:]]/}" ]] && continue

	name=$(awk '{print $1}' <<< "$line")
	expected=$(awk '{print $2}' <<< "$line")
	[ -z "$name" ] || [ -z "$expected" ] && continue

	# Collect ALL define occurrences of this symbol across the source tree.
	# Every occurrence must agree with the baseline: a wrong shim in any TU
	# sends the wrong attribute to the kernel when that TU is compiled.
	actuals=$(awk -v n="$name" '$1==n{print $2}' <<< "$define_map" | sort -un)

	if [ -z "$actuals" ]; then
		# Symbol not found anywhere in the source tree -- it was likely
		# deleted without updating the baseline.
		echo "WARN: $NAME: $name not found in source tree shims" >&2
		missing=$((missing + 1))
		continue
	fi

	checked=$((checked + 1))
	while IFS= read -r actual; do
		if [ "$actual" != "$expected" ]; then
			echo "FAIL: $NAME: $name shim value wrong: have $actual, want $expected (baseline)" >&2
			fail=$((fail + 1))
		fi
	done <<< "$actuals"
done < "$BASELINE"

if [ "$fail" -gt 0 ]; then
	n=$(printf '%s\n' "$fail")
	echo "FAIL: $NAME: $n shim value mismatch(es) -- wrong wire attribute(s) sent to kernel (see stderr)"
	exit 1
fi

warn=""
[ "$missing" -gt 0 ] && warn=", $missing symbol(s) not found (WARN)"
[ "$missing" -gt 0 ] && exit 1
echo "PASS: $NAME ($checked shim value(s) verified against baseline$warn)"
exit 0
