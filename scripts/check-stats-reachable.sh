#!/bin/bash
#
# check-stats-reachable: audit that every scalar counter declared in
# struct stats_s is surfaced somewhere the operator can see -- via a
# STAT_FIELD() descriptor entry, a direct C-level reference, or an
# explicit allowlist for hand-emitted / macro-concatenated shadow
# counters.
#
# The dump renderer walks the stat_field descriptor tables in
# stats/stats.c and stats/json_dump.c and emits one JSON key per row.
# A field added to struct stats_s without a matching STAT_FIELD() row
# (or an alternative emission path) is a "dead counter": bumped inside
# the child, but never printed, never scraped, never useful.  Fable
# and codex triage lean on the JSON dump to decide whether a strategy
# is exercising the kernel, so a dead counter looks identical to a
# broken strategy from the outside.
#
# This script makes the "is this counter dead?" question mechanical:
#
#   1. Enumerate the scalar field names declared inside
#      `struct stats_s { ... }` in include/stats.h.
#
#   2. Build the REACHABLE set from three sources:
#      a) STAT_FIELD(prefix, suffix) / STAT_FIELD_JSON(prefix, suffix, ...)
#         invocations in stats/stats.c and stats/json_dump.c.  These
#         concatenate prefix + "_" + suffix to form the struct field
#         name, so the literal token never appears in the source --
#         extract it symbolically.
#      b) Every whole-word occurrence of a field name in any *.c file
#         in the tree.  Covers direct writes (shm->stats.foo++),
#         offsetof() lookups, sizeof() references, etc.
#      c) An explicit ALLOWLIST of known-intentional hand-rolled /
#         loop-emitted / shadow counters that neither route (a) nor
#         (b) catches -- typically per-syscall / per-group arrays and
#         macro-concatenated dispatch tables.
#
#   3. Print every stats_s field NOT in REACHABLE and NOT covered by
#      the allowlist.  Exit 0 if the set is empty, non-zero (with the
#      list on stderr) otherwise.
#
# The allowlist is tuned so this script exits 0 on the current tree.
# Its purpose is to catch FUTURE fields that ship without an emission
# path -- add a counter, forget the STAT_FIELD row, this trips.
#
# Wire-up into scripts/check-static.sh is intentionally deferred:
# check-static is a fleet-visible gate and this audit needs a burn-in
# window against the allowlist policy before it becomes load-bearing.
# For now the script is standalone; invoke directly.

set -u

NAME="check-stats-reachable"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

STATS_H="$ROOT/include/stats.h"
STATS_C_FILES=("$ROOT/stats/stats.c" "$ROOT/stats/json_dump.c")

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$STATS_H" ] || fail "cannot read $STATS_H"
for f in "${STATS_C_FILES[@]}"; do
	[ -r "$f" ] || fail "cannot read $f"
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FIELDS="$TMP/fields"
STATFIELDS="$TMP/statfields"
TOKENS="$TMP/tokens"
REACHABLE="$TMP/reachable"
UNREACHED="$TMP/unreached"
UNALLOWED="$TMP/unallowed"

# ---------------------------------------------------------------------
# Step 1: enumerate scalar field names inside struct stats_s.
#
# The struct body runs from `struct stats_s {` to the terminating
# `};`.  Field decls take the form
#     <type> <name>[<dim>]... [__attribute__((...))];
# where <type> is one of the fundamental unsigned-integer types used
# throughout the struct.  Array dimensions (possibly multi-dim) and
# alignment attributes are stripped to leave the bare identifier.
# ---------------------------------------------------------------------
awk '/^struct stats_s \{/,/^\};/' "$STATS_H" | \
	grep -E '^[[:space:]]+(uint16_t|uint32_t|uint64_t|unsigned int|unsigned long long|unsigned long)[[:space:]]+' | \
	sed -E \
		-e 's/^[[:space:]]+(uint16_t|uint32_t|uint64_t|unsigned int|unsigned long long|unsigned long)[[:space:]]+//' \
		-e 's/(\[[^]]+\])+.*$//' \
		-e 's/[[:space:]]*(__attribute__.*)?;.*$//' \
		-e 's/[[:space:]]+$//' | \
	sort -u > "$FIELDS"

field_count="$(wc -l < "$FIELDS")"
if [ "$field_count" -lt 100 ]; then
	fail "extracted only $field_count fields from $STATS_H (parser broke?)"
fi

# ---------------------------------------------------------------------
# Step 2a: names constructed by STAT_FIELD() and STAT_FIELD_JSON().
#
# Both macros build the struct field name as `cat##_##suffix`, so the
# literal identifier is never present in the source.  Recover it by
# matching the macro invocation and joining the two arguments with
# an underscore.
# ---------------------------------------------------------------------
grep -hoE 'STAT_FIELD(_JSON)?\([[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' "${STATS_C_FILES[@]}" | \
	sed -E 's/STAT_FIELD(_JSON)?\([[:space:]]*//; s/[[:space:]]*,[[:space:]]*/_/' | \
	sort -u > "$STATFIELDS"

# ---------------------------------------------------------------------
# Step 2b: every identifier token that appears in any *.c file.
#
# Any field referenced via `shm->stats.foo`, `->stats.foo`,
# `parent_stats.foo`, `offsetof(struct stats_s, foo)`, or a
# `sizeof()` shows up here.  Restricting to *.c avoids counting the
# declaration itself in stats.h as a "reference".
# ---------------------------------------------------------------------
find "$ROOT" -name '*.c' -type f -print0 | \
	xargs -0 grep -hoE '\b[a-zA-Z_][a-zA-Z0-9_]*\b' | \
	sort -u > "$TOKENS"

# Fields reached directly (present as an identifier in some .c file)
# unioned with those reached through the STAT_FIELD() macro.
comm -12 "$FIELDS" "$TOKENS" > "$TMP/direct"
sort -u "$STATFIELDS" "$TMP/direct" > "$REACHABLE"

comm -23 "$FIELDS" "$REACHABLE" > "$UNREACHED"

# ---------------------------------------------------------------------
# Step 3: allowlist known-intentional residue.
#
# Patterns are anchored ERE regexes matched against the whole field
# name.  Categories:
#
#   * Hand-emitted per-syscall / per-group arrays.  These are `unsigned
#     long name[MAX_NR_SYSCALL]` (or [NR_..._GROUPS]) fields walked
#     directly by dedicated dump helpers in stats/stats.c that pass
#     the array pointer to a topN emitter.  There is no STAT_FIELD row
#     and the array name may or may not be spelled in a .c file
#     depending on whether the walker lives in the same TU.
#
#   * Multi-dim shadow histories (childop_edge_history,
#     childop_wall_history).  Consumed via reservoir-style summaries;
#     the raw array is not row-emitted.
#
#   * Family-indexed dispatch tables (genl_family_calls_*,
#     cmp_frontier_*, frontier_frseq_*) whose emission goes through a
#     custom walker rather than a STAT_FIELD row.
#
#   * Macro-concatenated dispatch (nftables_churn_*_expr_emit) --
#     addressed via `offsetof(struct stats_s,
#     nftables_churn_##field##_expr_emit)` in the nft_expr_table[]
#     descriptor.  Preprocessor concatenation means the literal
#     identifier never appears in any .c file.
#
#   * Explicit dead-counter escrow.  The three names below have no
#     writer, no reader, and no dump-side emission in the current
#     tree.  They are pre-existing residue predating this audit --
#     listed here so the script exits 0 on master, and called out in
#     the commit message that introduced this audit so a follow-up
#     can either wire them up or delete them.  Do NOT extend this
#     block silently: a new unreachable field means either a missing
#     STAT_FIELD row (fix the omission) or a genuinely dead counter
#     (delete it or file a follow-up).
# ---------------------------------------------------------------------
ALLOWLIST_PATTERNS=(
	'.*_per_syscall'
	'.*_per_group'
	'childop_edge_history'
	'childop_wall_history'
	'genl_family_calls_.*'
	'cmp_frontier_.*'
	'frontier_frseq_.*'
	'nftables_churn_.*_expr_emit'
	# Pre-existing dead-counter escrow -- see block comment above.
	'local_obj_num_entries_corrupted'
	'perf_event_chains_pmu_unsupported'
	'tracefs_ftrace_subset_skipped'
)

# Join patterns into one anchored ERE alternation.  Anchoring both
# ends prevents a pattern like `.*_per_syscall` from accidentally
# matching a substring somewhere else.
allow_re="^($(IFS='|'; echo "${ALLOWLIST_PATTERNS[*]}"))\$"

grep -Ev "$allow_re" "$UNREACHED" > "$UNALLOWED" || true

if [ -s "$UNALLOWED" ]; then
	echo "FAIL: $NAME: struct stats_s fields with no STAT_FIELD row, no C reference, and no allowlist entry:" >&2
	sed 's/^/  /' "$UNALLOWED" >&2
	echo "" >&2
	echo "Either add a STAT_FIELD(prefix, suffix) descriptor row in" >&2
	echo "stats/stats.c or stats/json_dump.c so the dump renderer" >&2
	echo "surfaces the counter, or remove the field." >&2
	echo "If the counter is emitted through a bespoke walker, extend the" >&2
	echo "allowlist in $0 with a specific pattern and a comment explaining" >&2
	echo "the emission path." >&2
	exit 1
fi

echo "PASS: $NAME: $field_count stats_s fields, all reachable or allowlisted"
exit 0
