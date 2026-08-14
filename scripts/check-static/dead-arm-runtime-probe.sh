#!/bin/bash
#
# dead-arm-runtime-probe: verify that the access-after-cap-drop runtime
# dead-arm probes exist and are wired into the dead-arm reporting surface.
#
# Background: dead-arm-config.sh catches CONFIG_*-gated arms at build
# time, but two classes of arm are config-live and runtime-dead:
#
#   tracefs-fuzzer: CONFIG_FTRACE=y / kernel has tracefs, but the fuzz
#     user's capability set after cap-drop does not allow writes.
#     Probe: access(tracefs_root/tracing_on, W_OK) in child context.
#
#   afxdp-churn: CONFIG_XDP_SOCKETS=y but socket(AF_XDP) returns EPERM/
#     EACCES because the fuzz user lacks CAP_NET_RAW after cap-drop.
#     Probe: errno check on socket(AF_XDP) → ns_cap_denied_afxdp latch.
#
# MAPPING TABLE
# Each row: childop<TAB>probe_kind<TAB>stats_field<TAB>emitter_symbol
#
#   childop       - name of the childop (matches files under childops/)
#   probe_kind    - grep-E pattern checked against the childop's source files
#   stats_field   - subsys.field form; field is checked in the stats header,
#                   the dotted form is checked in subsystems.c and json/tail.c
#   emitter_symbol - verdict enum token checked in stats/arm-verdict.h
#
# Each check requires at least one match.  Fail-closed: zero matches is a
# hard FAIL.  Row-count assertion prevents a silently-emptied table from
# appearing to pass.
#
# Severity: FAIL (exit 1) -- these probes are part of the correctness
# contract for the dead-arm detection surface.

set -u

NAME="dead-arm-runtime-probe"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# ---- Mapping table (tab-separated) ----
# Format: childop<TAB>probe_kind<TAB>stats_field<TAB>emitter_symbol
MAPPING=$(cat <<'EOF'
tracefs-fuzzer	access\(.*W_OK\)	tracefs_fuzzer.runtime_cap_denied	ARM_VERDICT_RUNTIME_DEAD
afxdp-churn	ns_cap_denied_afxdp	afxdp_churn.setup_failed_cap_denied	ARM_VERDICT_RUNTIME_DEAD
EOF
)

# Count real mapping entries (non-comment, non-blank).
map_entries=$(printf '%s\n' "$MAPPING" | grep -cvE '^[[:space:]]*#|^[[:space:]]*$')

# Minimum arm count: shrinking the table below this is a hard FAIL.
MIN_ARMS=2

if [ "$map_entries" -lt "$MIN_ARMS" ]; then
	echo "FAIL: $NAME: mapping table has $map_entries arm(s); expected at least $MIN_ARMS"
	exit 1
fi

# ---- Pre-validate mapping: every real row must have exactly 4 tab-separated
# non-empty fields.  awk -F'\t' detects empty interior fields that IFS=$'\t'
# read would silently shift away. ----
_map_bad=$(printf '%s\n' "$MAPPING" | \
	awk -F'\t' '
		/^[[:space:]]*#/ { next }
		/^[[:space:]]*$/ { next }
		NF != 4 || $1=="" || $2=="" || $3=="" || $4=="" {
			printf "  %s: malformed row (NF=%d, expected 4 non-empty tab-separated fields): %s\n", name, NF, $0
		}
	' name="$NAME")
if [ -n "$_map_bad" ]; then
	printf '%s\n' "$_map_bad" >&2
	echo "FAIL: $NAME: mapping table has rows with wrong field count (expected exactly 4 tab-separated fields)"
	exit 1
fi

fail_count=0

check_match() {
	local label="$1"
	local file="$2"
	local pattern="$3"
	local count

	count=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
	if [ "${count:-0}" -eq 0 ]; then
		echo "FAIL: $NAME: $label: pattern '$pattern' not found in $file" >&2
		fail_count=$((fail_count + 1))
	fi
}

# check_in_childop: assert pattern found in at least one source file for
# the named childop.  Files are found via glob under childops/.
# Fails if no files match the glob (probe removed) or no file contains
# the pattern (probe present but probe token absent).
# C comments are stripped before matching so comment-only occurrences
# (e.g. a token mentioned in a block comment but not in live code) are
# not counted as present.
check_in_childop() {
	local label="$1"
	local childop="$2"
	local pattern="$3"
	local found_files=0
	local matched=0
	local f count

	shopt -s globstar nullglob 2>/dev/null
	for f in childops/**/*"${childop}"* childops/*"${childop}"*; do
		# skip directories
		[ -f "$f" ] || continue
		# restrict to source files; build artifacts (.o, .d, etc.) must not
		# satisfy the probe — they can outlive the source after a deletion
		case "$f" in *.c|*.h) ;; *) continue ;; esac
		found_files=$((found_files + 1))
		# Strip C block and line comments before grepping so that a
		# token mentioned only in a comment does not count as present.
		count=$(perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' "$f" 2>/dev/null | \
			grep -cE "$pattern" 2>/dev/null || true)
		if [ "${count:-0}" -gt 0 ]; then
			matched=$((matched + 1))
		fi
	done

	if [ "$found_files" -eq 0 ]; then
		echo "FAIL: $NAME: $label: no source files found for childop '$childop'" >&2
		fail_count=$((fail_count + 1))
		return
	fi
	if [ "$matched" -eq 0 ]; then
		echo "FAIL: $NAME: $label: pattern '$pattern' not found in any $childop source file" >&2
		fail_count=$((fail_count + 1))
	fi
}

# ---- Walk the mapping table ----
arms_walked=0

while IFS=$'\t' read -r childop probe_kind stats_field emitter_symbol; do
	[ -n "$childop" ] || continue
	[[ "$childop" =~ ^[[:space:]]*# ]] && continue

	# Derive subsys and field from stats_field (e.g. tracefs_fuzzer.runtime_cap_denied)
	subsys="${stats_field%%.*}"
	field="${stats_field#*.}"

	# 1. Probe pattern present in childop source files (comments stripped)
	check_in_childop \
		"$childop probe present in childop source" \
		"$childop" \
		"$probe_kind"

	# 1b. Stats field token present in at least one childop source file.
	# This ensures the actual stats write (e.g. setup_failed_cap_denied
	# or runtime_cap_denied) is present in the childop implementation,
	# not merely in stats/ headers or emitters checked by steps 2-4.
	check_in_childop \
		"$childop $field present in childop source" \
		"$childop" \
		"$field"

	# 2. Stats field declared in the subsystem's stats header
	check_match \
		"$childop $field in stats header" \
		"stats/subsys/${subsys}.h" \
		"$field"

	# 3. Dotted stats_field wired in the dead-arm check (subsystems.c)
	check_match \
		"$childop ${stats_field} wired in subsystems.c" \
		"stats/dump/subsystems.c" \
		"${subsys}\\.${field}"

	# 4. JSON emitter covers the runtime_dead case (json/tail.c)
	check_match \
		"$childop JSON dead-arm emitter in tail.c" \
		"stats/json/tail.c" \
		"${subsys}.*${field}|${field}.*${subsys}"

	# 5. Verdict token present in the shared verdict enum
	check_match \
		"$emitter_symbol in arm-verdict.h" \
		"stats/arm-verdict.h" \
		"$emitter_symbol"

	arms_walked=$((arms_walked + 1))
done <<< "$MAPPING"

# ---- Row-count assertion ----
if [ "$arms_walked" -ne "$map_entries" ]; then
	echo "FAIL: $NAME: walked $arms_walked arm(s) but mapping has $map_entries entries" >&2
	fail_count=$((fail_count + 1))
fi

# ---- Reverse check: emission sites must match table rows ----
subsys_count=$(grep -c 'RUNTIME_DEAD_ARM"' stats/dump/subsystems.c 2>/dev/null)
tail_count=$(grep -c 'ARM_VERDICT_RUNTIME_DEAD' stats/json/tail.c 2>/dev/null)
if [ "$subsys_count" -ne "$map_entries" ]; then
	echo "FAIL: $NAME: stats/dump/subsystems.c has $subsys_count RUNTIME_DEAD_ARM emission(s); expected $map_entries (one per table row)" >&2
	exit 1
fi
if [ "$tail_count" -ne "$map_entries" ]; then
	echo "FAIL: $NAME: stats/json/tail.c has $tail_count ARM_VERDICT_RUNTIME_DEAD emission(s); expected $map_entries (one per table row)" >&2
	exit 1
fi

# ---- Final verdict ----

if [ "$fail_count" -gt 0 ]; then
	echo "FAIL: $NAME: $fail_count check(s) failed -- runtime dead-arm probes missing or unwired"
	exit 1
fi

echo "PASS: $NAME: all $arms_walked runtime dead-arm probe arm(s) present and wired"
exit 0
