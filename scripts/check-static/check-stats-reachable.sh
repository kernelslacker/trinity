#!/bin/bash
#
# check-stats-reachable: audit that every scalar counter in the
# stats_s tree -- flat top-level members AND every leaf inside a
# nested struct stats/subsys/*.h header -- is surfaced somewhere the
# operator can see, either via a STAT_FIELD*() descriptor row or via a
# consumer-side read (never via a producer write alone).
#
# The dump renderer walks stat_field descriptor tables that emit one
# JSON key per row.  A field added to a struct stats_s member (flat or
# nested) without a matching STAT_FIELD*() row -- and without any
# rendered read on some emit path -- is a "dead counter": bumped
# inside the child, but never printed, never scraped, never useful.
# Downstream triage relies on the JSON dump to decide whether a
# strategy is exercising the kernel, so a dead counter looks
# identical to a broken strategy from the outside.
#
# The pre-refactor version of this script only walked the flat
# scalars in struct stats_s and treated ANY whole-word occurrence in
# a *.c file (including `shm->stats.foo++` producer writes) as
# reachability evidence.  That left ~1300+ scalar leaves living in
# stats/subsys/*_stats sub-structs completely unaudited, and let a
# produced-but-never-rendered counter pass silently because its own
# `++` looked identical to a render-side read.  Both holes are
# closed here:
#
#   1. Enumerate scalar field names by structurally walking:
#      a) flat scalars declared directly in `struct stats_s { ... }`
#         in include/stats.h;
#      b) every scalar leaf reachable from a `struct <X>_stats <mbr>`
#         member of stats_s by descending through the corresponding
#         `struct <X>_stats { ... };` definition in stats/subsys/*.h.
#         Descent is recursive: `struct frontier_stats` is composed of
#         `struct frontier_core_stats core`, `struct
#         frontier_per_syscall_stats per_syscall`, ... so the leaves
#         come out as `frontier.core.strategy_picks`,
#         `frontier.per_syscall.live_picks_per_syscall`, etc.
#      Every leaf is stored as its fully-qualified access path from
#      stats_s (flat: `foo`; nested: `member.leaf` /
#      `member.sub.leaf`).
#
#   2. Build the REACHABLE set from four independent sources:
#      a) STAT_FIELD(cat, suffix) / STAT_FIELD_JSON(cat, suffix, ...)
#         invocations.  Both macros build the flat identifier as
#         `cat##_##suffix` via preprocessor concatenation, so the
#         literal token never appears -- recover it symbolically.
#      b) STAT_FIELD_SUB(sub, field) / STAT_FIELD_JSON_SUB(sub, field,
#         ...) invocations.  These expand to
#         `offsetof(struct stats_s, sub.field)` -- recover the
#         qualified `sub.field` symbolically.
#      c) Bespoke offset-based descriptor rows that spell the field
#         out literally: `offsetof(struct stats_s, member.sub.leaf)`.
#         The stats/periodic/counter-rates.c per-rate tables, the
#         stats/dump/oracle.c anomaly rows via ORACLE_ANOMALY_ROW,
#         and stats/categories/*.c per-index arrays all land here.
#      d) A rendered CONSUMER read: `shm->stats.<path>` /
#         `(&)shm->stats.<path>` occurring on a line that is NOT a
#         producer write.  A line is treated as a producer write if
#         either (i) the reference is immediately followed by an
#         assignment / compound-assignment / post-inc/-dec operator,
#         or (ii) the line invokes any mutating __atomic_*
#         primitive (add / sub / store / exchange / and / or / xor /
#         fetch / compare_exchange).  Non-mutating primitives
#         (__atomic_load_n) are left alone, so a field loaded into a
#         local and then rendered counts as reached.
#
#      A produced-but-never-rendered field satisfies none of (a)-(d)
#      -- it has a write line but no read line, no descriptor row,
#      no offsetof entry -- and drops through to step 3.
#
#   3. Print every field NOT in REACHABLE and NOT covered by the
#      allowlist.  Exit 0 if the residue is empty, non-zero (with
#      the list on stderr) otherwise.
#
# The allowlist is tuned so this script exits 0 on the current tree.
# Its purpose is to catch FUTURE fields that ship without an emission
# path -- add a counter, forget the descriptor row / bespoke emit,
# this trips.

set -u

# Bytewise sort order everywhere so `comm` doesn't trip on locale
# collation drift between Python (codepoint) and shell sort (locale).
export LC_ALL=C

NAME="check-stats-reachable"

ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

STATS_H="$ROOT/include/stats.h"
SUBSYS_DIR="$ROOT/stats/subsys"

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -r "$STATS_H" ] || fail "cannot read $STATS_H"
[ -d "$SUBSYS_DIR" ] || fail "cannot read subsys dir $SUBSYS_DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FIELDS="$TMP/fields"
DESC="$TMP/desc"
REFS="$TMP/refs"
OFF="$TMP/off"
REACHABLE="$TMP/reachable"
UNREACHED="$TMP/unreached"
UNALLOWED="$TMP/unallowed"
CFILES="$TMP/cfiles"
HFILES="$TMP/hfiles"
CFILES_NORM="$TMP/cfiles_norm.txt"
HFILES_NORM="$TMP/hfiles_norm.txt"

# NUL-delimited file lists reused by several xargs passes.
find "$ROOT" -name '*.c' -type f -print0 > "$CFILES"
find "$SUBSYS_DIR" "$ROOT/include" -maxdepth 1 -name '*.h' -type f > "$HFILES"

# join_continuations: normalise continuation lines so that two-line
# calls like
#   __atomic_fetch_add(
#           &shm->field, ...
# and
#   .offset = offsetof(struct stats_s,
#                      member.sub.leaf)
# are presented as a single line to write-pattern matchers and to the
# offsetof extractor (step 2c).  Without this join:
#  - The __atomic_*( continuation line carries &shm->field but not the
#    __atomic_( token, so write-exclusion filters that look for both
#    tokens on the same line classify the continuation as a false read.
#  - The offsetof continuation line carries the dotted field path but
#    not "offsetof(struct stats_s,", so the step-2c extractor cannot
#    capture the path and treats the field as unreachable.
# One level of join is sufficient for all spellings observed in this
# tree; FNR==1 resets state at each file boundary so awk file-batching
# cannot bleed pending state across files.
join_continuations() {
	awk '
	FNR == 1 { pending = "" }
	pending != "" { print pending " " $0; pending = ""; next }
	/^[^)]*(__atomic_[a-z_]+|offsetof)\([^)]*$/ { pending = $0; next }
	{ print }
	END { if (pending != "") print pending }
	'
}

# Pre-build a single continuation-joined text file covering all C source
# files.  Steps 2c, 2d, and the shm_s write-site / read-set scans all
# read from this file, eliminating scattered per-step normalization.
# The awk body below is the same logic as join_continuations(); that
# shell function exists for the self-test where we pipe a small fixture
# through it directly.  xargs passes all file paths as arguments; FNR==1
# resets pending at each file boundary so multi-batch invocations are safe.
xargs -0 awk '
FNR == 1 { pending = "" }
pending != "" { print pending " " $0; pending = ""; next }
/^[^)]*(__atomic_[a-z_]+|offsetof)\([^)]*$/ { pending = $0; next }
{ print }
END { if (pending != "") print pending }
' < "$CFILES" > "$CFILES_NORM"

# Pre-build a single continuation-joined text file covering all header
# files.  The read-scan arms in step 2d and the shm_s read scan both
# consume this file so that a field access split across two header lines
# is not invisible to the write-exclusion filter.  HFILES is
# newline-delimited (not NUL-delimited), so xargs without -0 is used;
# FNR==1 resets pending at each file boundary.
xargs awk '
FNR == 1 { pending = "" }
pending != "" { print pending " " $0; pending = ""; next }
/^[^)]*(__atomic_[a-z_]+|offsetof)\([^)]*$/ { pending = $0; next }
{ print }
END { if (pending != "") print pending }
' < "$HFILES" > "$HFILES_NORM"

# ---------------------------------------------------------------------
# Field enumeration.
#
# Emits fully-qualified access paths from stats_s to every scalar leaf:
#     foo                                       flat top-level
#     accept_unblocker.connects_fired           nested one deep
#     frontier.core.strategy_picks              nested two deep
#
# Implemented as a single awk pass that indexes every
# `struct <X>_stats { ... };` block in stats.h + include/*.h +
# stats/subsys/*.h, then walks stats_s recursively.  Recursion is
# capped at depth 8 as a safety valve; the current tree only nests
# two levels (frontier -> core / per_syscall / ...).
# ---------------------------------------------------------------------
awk_enum() {
	awk '
	function is_scalar(t) {
		return t == "uint16_t" || t == "uint32_t" || t == "uint64_t" ||
		       t == "unsigned" || t == "unsignedint" ||
		       t == "unsignedlong" || t == "unsignedlonglong"
	}
	BEGIN { cur = "" }
	{
		line = $0
		if (match(line, /^struct [a-zA-Z_][a-zA-Z0-9_]*(_stats|_s) \{/)) {
			# Capture struct name (drop leading "struct ", trailing " {").
			s = substr(line, RSTART, RLENGTH)
			sub(/^struct /, "", s); sub(/ \{$/, "", s)
			cur = s
			next
		}
		if (cur != "" && line ~ /^\};/) { cur = ""; next }
		if (cur == "") next
		# Strip leading whitespace, trailing comments.
		sub(/^[[:space:]]+/, "", line)
		sub(/\/\*.*/, "", line)
		sub(/\/\/.*/, "", line)
		sub(/[[:space:]]*(__attribute__.*)?;.*$/, "", line)
		sub(/[[:space:]]+$/, "", line)
		if (line == "") next
		# Nested struct member?
		if (match(line, /^struct [a-zA-Z_][a-zA-Z0-9_]*_stats[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)) {
			m = substr(line, RSTART, RLENGTH)
			sub(/^struct /, "", m)
			# Split into "<sname> <member>" and strip array dims.
			gsub(/\[[^]]+\]/, "", m)
			n = split(m, parts, /[[:space:]]+/)
			# parts[1] = <sname>, parts[2] = <member>
			print "NEST\t" cur "\t" parts[2] "\t" parts[1]
			next
		}
		# Scalar?  Type may be one or two tokens ("unsigned long").
		# Split on whitespace, join type tokens until an identifier
		# starting with a letter (the field name) shows up.
		n = split(line, parts, /[[:space:]]+/)
		type = ""
		field = ""
		for (i = 1; i <= n; i++) {
			p = parts[i]
			# Type keyword?
			if (p == "uint16_t" || p == "uint32_t" || p == "uint64_t" ||
			    p == "unsigned" || p == "int" || p == "long" || p == "signed") {
				type = type p
				continue
			}
			field = p
			break
		}
		if (field == "" || !is_scalar(type)) next
		# Strip array dims from the field name.
		gsub(/\[[^]]+\]/, "", field)
		if (field == "") next
		print "SCALAR\t" cur "\t" field
	}
	' "$@"
}

# Build the struct index (all struct definitions), then walk.
awk_enum "$STATS_H" $(cat "$HFILES") > "$TMP/index"

# Walk stats_s recursively into a fully-qualified leaf list.
python3 - "$TMP/index" > "$FIELDS" <<'PY'
import sys, collections
scalars = collections.defaultdict(list)   # struct -> [(field), ...]
nested  = collections.defaultdict(list)   # struct -> [(member, child_struct), ...]
with open(sys.argv[1]) as fh:
    for row in fh:
        parts = row.rstrip("\n").split("\t")
        kind = parts[0]
        if kind == "SCALAR":
            _, s, field = parts
            scalars[s].append(field)
        elif kind == "NEST":
            _, s, member, child = parts
            nested[s].append((member, child))

out = []
def walk(struct, prefix, depth):
    if depth > 8:
        return
    for f in scalars.get(struct, ()):
        out.append(prefix + f)
    for m, child in nested.get(struct, ()):
        walk(child, prefix + m + ".", depth + 1)

walk("stats_s", "", 0)
for name in sorted(set(out)):
    print(name)
PY

field_count="$(wc -l < "$FIELDS")"
# Sanity floor.  The pre-refactor scalar-only walker found ~30 flat
# fields; the structural walker adds ~1300+ nested leaves across the
# stats/subsys/ tree.  If we drop under 500 the enumeration has
# broken.
if [ "$field_count" -lt 500 ]; then
	fail "extracted only $field_count fields (structural walker broke?)"
fi

# ---------------------------------------------------------------------
# Reachability step 2a: flat STAT_FIELD / STAT_FIELD_JSON.
# Emits `cat_suffix` (macro-concatenated identifier).
# $HFILES_NORM is also scanned so that a STAT_FIELD*() invocation in
# an inline header helper is not invisible to this pass.
# ---------------------------------------------------------------------
{ xargs -0 grep -hoE 'STAT_FIELD(_JSON)?\([[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' < "$CFILES" 2>/dev/null; \
  grep -hoE 'STAT_FIELD(_JSON)?\([[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' "$HFILES_NORM" 2>/dev/null; } | \
	sed -E 's/STAT_FIELD(_JSON)?\([[:space:]]*//; s/[[:space:]]*,[[:space:]]*/_/' \
	> "$DESC.flat"

# ---------------------------------------------------------------------
# Reachability step 2b: STAT_FIELD_SUB / STAT_FIELD_JSON_SUB.
# Emits `sub.field` (offsetof-based, member expressed literally).
# $HFILES_NORM is also scanned so that a STAT_FIELD_SUB*() invocation
# in an inline header helper is not invisible to this pass.
# ---------------------------------------------------------------------
{ xargs -0 grep -hE 'STAT_FIELD_(JSON_)?SUB\([[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' < "$CFILES" 2>/dev/null; \
  grep -hE 'STAT_FIELD_(JSON_)?SUB\([[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*' "$HFILES_NORM" 2>/dev/null; } | \
	sed -E 's/.*STAT_FIELD_(JSON_)?SUB\([[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*,[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*).*/\2.\3/' \
	> "$DESC.sub"

# ---------------------------------------------------------------------
# Reachability step 2c: bespoke offsetof(struct stats_s, path) entries.
# Extract the full dotted path (may be multi-level, e.g. frontier.core.foo).
# $CFILES_NORM is used so that two-line offsetof entries such as:
#   .offset = offsetof(struct stats_s,
#                      frontier.discriminator.frseq_candidates) },
# are joined into a single line before extraction.
# ---------------------------------------------------------------------
grep -hoE 'offsetof\(struct stats_s,[[:space:]]*[a-zA-Z_][a-zA-Z0-9_.]*' "$CFILES_NORM" 2>/dev/null | \
	sed -E 's/offsetof\(struct stats_s,[[:space:]]*//' \
	> "$OFF"

# ---------------------------------------------------------------------
# Reachability step 2d: consumer reads.
#
# Match `stats.<path>` where <path> is one or more dot-joined
# identifiers.  Drop any line where the reference is followed by a
# write operator, and any line that also invokes a mutating
# __atomic_* primitive (which typically takes `&stats.foo` as its
# first arg and rewrites it in-place).  Everything left is a read
# on some render path.
#
# Input is $CFILES_NORM (continuation-joined) rather than raw source
# so that two-line writes:
#   __atomic_add_fetch(
#           &shm->stats.foo.bar, 1, __ATOMIC_RELAXED);
# arrive as a single joined line that the __atomic_ filter below
# correctly excludes.  Without the join, the continuation line carries
# &shm->stats.foo.bar but not the __atomic_( token and passes through
# as a false read, wrongly marking the field reachable.
#
# $HFILES_NORM (continuation-joined header stream) is also scanned so
# that stats references in inline helpers in include/*.h are not
# invisible to this pass.  Using the joined form means a field access
# split across two header lines is correctly seen by the write-exclusion
# filter rather than arriving as a false read on the continuation line.
# ---------------------------------------------------------------------
{ grep -hE '\bstats(\.[a-zA-Z_][a-zA-Z0-9_]*)+\b' "$CFILES_NORM" 2>/dev/null; \
  grep -hE '\bstats(\.[a-zA-Z_][a-zA-Z0-9_]*)+\b' "$HFILES_NORM" 2>/dev/null; } | \
	grep -vE '\bstats(\.[a-zA-Z_][a-zA-Z0-9_]*)+(\[[^]]*\])?[[:space:]]*(\+\+|--|=|\+=|-=|\*=|/=|<<=|>>=|&=|\|=|\^=)' | \
	grep -vE '__atomic_(add|sub|store|exchange|and|or|xor|fetch|compare)' | \
	grep -oE '\bstats(\.[a-zA-Z_][a-zA-Z0-9_]*)+\b' | \
	sed 's/^stats\.//' \
	> "$REFS"

# Combined REACHABLE set.  All emit paths canonicalise leaves to the
# same dotted-path form as $FIELDS.
sort -u "$DESC.flat" "$DESC.sub" "$OFF" "$REFS" > "$REACHABLE"

comm -23 "$FIELDS" "$REACHABLE" > "$UNREACHED"

# ---------------------------------------------------------------------
# Step 3: allowlist known-intentional residue.
#
# Categories:
#
#   * Per-syscall / per-group arrays walked by dedicated topN emitters
#     (`.*_per_syscall`, `.*_per_group`) -- the walker sits in
#     stats/stats.c / stats/dump/*.c and passes the array pointer
#     rather than spelling the field, so no ref pattern catches them.
#
#   * Multi-dim shadow histories (`.*_history`) whose raw arrays are
#     consumed via reservoir-style summaries, not row-emitted.
#
#   * Family-indexed dispatch tables (genl_family_calls_.*) still on
#     the flat side, walked by a bespoke emitter.
#
#   * Macro-concatenated dispatch (nftables_churn_.*_expr_emit /
#     nftables_churn\..*_expr_emit) -- addressed via
#     `offsetof(struct stats_s, nftables_churn_##field##_expr_emit)`
#     in the nft_expr_table[] descriptor.  Preprocessor concatenation
#     hides the literal identifier from every text scan.
#
#   * ORACLE_ANOMALY_ROW-emitted diagnostic counters
#     (diag.statmount_setup_fail) whose macro invocation spells the
#     field bare (`diag.statmount_setup_fail`) with no `stats.`
#     prefix.  The macro itself expands to `offsetof(struct stats_s,
#     field_)` at the definition site -- preprocessor swap hides the
#     literal from our offsetof scan.
#
#   * Explicit dead-counter escrow.  Producer-only counters (writer
#     but no reader, no descriptor row, no bespoke emit) that
#     predate this audit.  Listed here so the script exits 0 on
#     master; a follow-up either wires them up or deletes them.
#     Do NOT extend this block silently: a new unreachable field
#     means either a missing descriptor row (fix the omission) or a
#     genuinely dead counter (delete it or file a follow-up).
# ---------------------------------------------------------------------
ALLOWLIST_PATTERNS=(
	# --- flat ---
	'.*_per_syscall'
	'.*_per_group'
	'genl_family_calls_.*'

	# --- nested: per-slot / walker-emitted arrays and shadow histories ---
	'[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*_per_syscall'
	'[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*_per_group'
	'[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*\.[a-zA-Z_][a-zA-Z0-9_]*_history'

	# --- nested: ORACLE_ANOMALY_ROW bespoke emit ---
	'diag\.statmount_setup_fail'

	# --- internal bookkeeping fields: not counters for external reports ---
	# tracefs_fuzzer.ftrace_subset_skipped: declared as a forward-carved
	#   slot for a future ftrace-subset dispatcher; no live producer.
	# transition_edge.calls_at_window_start: per-strategy window-start
	#   snapshot (atomic_store, not monotonic counter); internal bandit
	#   bookkeeping, not an externally reportable metric.
	# transition_edge.calls_by_strategy: per-strategy accumulated call
	#   counter (array, one slot per strategy).  Written from
	#   per-syscall-edges.c; read ONLY to seed calls_at_window_start via
	#   __atomic_load_n inside strategy-rotate.c's __atomic_store_n
	#   call.  The load+store appear on a single joined line after the
	#   continuation fix, so the __atomic_store_n filter correctly
	#   excludes the line from the consumer-read set.  Internal bandit
	#   window-delta bookkeeping; not an externally reportable metric.
	'tracefs_fuzzer\.ftrace_subset_skipped'
	'transition_edge\.calls_at_window_start'
	'transition_edge\.calls_by_strategy'

	# --- explicit dead-counter escrow: newly visible after multiline-write fix ---
	# pc_edge_source.errno_saves: per-syscall array written from
	#   minicorpus_save_with_reason() (persist/minicorpus-save.c) for
	#   errno-provenance-tagged corpus admissions.  Mirrors rq_saves[]
	#   which is rendered in stats/periodic/top-syscalls.c; errno variant
	#   has no render path yet.  Exposed as dead by the multiline-write
	#   fix (was falsely reachable via continuation-line false read).
	# pc_edge_source.errno_pcedge_wins: per-syscall array written from
	#   frontier_record_new_edge() (strategy/strategy-frontier.c) for
	#   errno-sourced PC-edge wins.  Mirrors rq_pcedge_wins[] (rendered
	#   in top-syscalls.c); errno variant has no render path yet.
	'pc_edge_source\.errno_saves'
	'pc_edge_source\.errno_pcedge_wins'
)

allow_re="^($(IFS='|'; echo "${ALLOWLIST_PATTERNS[*]}"))\$"

grep -Ev "$allow_re" "$UNREACHED" > "$UNALLOWED" || true

if [ -s "$UNALLOWED" ]; then
	echo "FAIL: $NAME: stats_s fields with no descriptor row, no consumer read, and no allowlist entry:" >&2
	sed 's/^/  /' "$UNALLOWED" >&2
	echo "" >&2
	echo "Either add a STAT_FIELD*() descriptor row (STAT_FIELD /" >&2
	echo "STAT_FIELD_JSON for flat fields, STAT_FIELD_SUB /" >&2
	echo "STAT_FIELD_JSON_SUB for nested ones) so the dump renderer" >&2
	echo "surfaces the counter, or remove the field.  If the counter" >&2
	echo "is emitted through a bespoke walker, extend the allowlist" >&2
	echo "in $0 with a specific pattern and a comment explaining the" >&2
	echo "emission path." >&2
	exit 1
fi

echo "PASS: $NAME: $field_count stats_s fields (flat + nested), all reachable or allowlisted"

# =====================================================================
# shm_s scalar counter coverage (additive extension).
#
# The stats_s walker above covers shm->stats.<path>.  A scalar
# counter declared directly in struct shm_s -- e.g. nat_t_churn.lo_up_fail
# was written from rtnl_bring_lo_up / bring_lo_up (four __atomic sites)
# while still a shm_s member, with no render path, before commit
# 9c09cc25e898 ("lo_up_fail: wire into stats surface with four-site plumbing")
# moved it into struct nat_t_churn_stats where it is now
# correctly covered by STAT_FIELD_SUB(nat_t_churn, lo_up_fail) and a
# stat_row emit -- lies outside that population entirely: the stats_s walker cannot
# enumerate it, and the consumer-read grep only matches shm->stats.*,
# so a producer with no render path passes silently.  This section
# closes that gap without touching any existing logic.
#
# Population: scalar (non-array) members of struct shm_s in
# include/shm.h that have at least one counter write site (any of the
# nine spellings in SHM_WRITE_PAT_ATOMIC / shm_write_pat below).
#
# Each member in the population must either:
#   1. appear on a non-write, non-comment source line (evidence that
#      something reads the value back out), or
#   2. be listed in the explicit allowlist below.
#
# Population count is reported; zero is WARN (parser broken).
# =====================================================================

# ---------------------------------------------------------------------
# SHM_WRITE_PAT_ATOMIC: canonical atomic-write primitive set for shm_s
# scalars.  Used by shm_write_pat() which is called in BOTH Step 2
# (write-site detection → population) and Step 3 (write-line exclusion
# → read set).  A single definition here prevents the two stages from
# drifting apart.
#
# Seven primitives:
#   __atomic_add_fetch  __atomic_fetch_add   (increment / add RMW)
#   __atomic_store_n                         (plain store)
#   __atomic_compare_exchange_n              (CAS)
#   __atomic_exchange_n                      (swap)
#   __atomic_fetch_sub  __atomic_sub_fetch   (decrement / subtract RMW)
#
# Together with the two direct-operator forms in shm_write_pat() these
# cover all nine write spellings observed tree-wide.
# ---------------------------------------------------------------------
SHM_WRITE_PAT_ATOMIC='__atomic_(add_fetch|fetch_add|store_n|compare_exchange_n|exchange_n|fetch_sub|sub_fetch)'

# shm_write_pat FIELD
# Emit an ERE matching any write to shm->FIELD on a source line.
# Nine spellings:
#   atomic primitives (matched via SHM_WRITE_PAT_ATOMIC) whose first
#   pointer arg is &shm->FIELD -- anchored as \([[:space:]]*&shm->FIELD[[:space:]]*[,)]
#   so only the first-argument position matches, not a later read arg;
#   shm->FIELD++ / shm->FIELD--  (post-inc/dec);
#   shm->FIELD += / shm->FIELD -= (compound-assignment).
shm_write_pat() {
	local f="$1"
	printf '%s' "${SHM_WRITE_PAT_ATOMIC}\([[:space:]]*&shm->${f}[[:space:]]*[,)]|\bshm->${f}[[:space:]]*(\+\+|--|\+=|-=)"
}
SHM_H="$ROOT/include/shm.h"
[ -r "$SHM_H" ] || fail "cannot read $SHM_H"

SHM_SCALARS="$TMP/shm_scalars"
SHM_WRITTEN="$TMP/shm_written"
SHM_READ="$TMP/shm_read"
SHM_UNREACHED="$TMP/shm_unreached"
SHM_UNALLOWED="$TMP/shm_unallowed"

# Step 1: enumerate scalar direct members of struct shm_s.
# Track brace depth so nested anonymous struct/union bodies are skipped;
# only direct (depth-0) members are emitted.
# Excluded: arrays ([), bool, enum, pointer, lock_t, uid_t, struct members.
awk '
/^struct shm_s \{/ { in_s=1; depth=0; next }
!in_s { next }
{
    if (/\{/) depth++
    if (depth > 0 && /\}/) { depth--; next }
    if (depth > 0) next
    if (/^\};/) { in_s=0; next }
    line = $0
    sub(/\/\*.*/, "", line)
    sub(/[[:space:]]+$/, "", line)
    if (line !~ /^[[:space:]]*(unsigned[[:space:]]+(int|long|char)|uint8_t|uint16_t|uint32_t|uint64_t|int)[[:space:]]/) next
    if (line ~ /\[/) next
    gsub(/[[:space:]]*(__attribute__[^;]*)?[[:space:]]*;.*/, "", line)
    sub(/.*[[:space:]]/, "", line)
    if (line ~ /^[a-zA-Z_][a-zA-Z0-9_]*$/) print line
}
' "$SHM_H" | sort -u > "$SHM_SCALARS"

shm_scalar_count="$(wc -l < "$SHM_SCALARS")"
if [ "$shm_scalar_count" -eq 0 ]; then
	echo "WARN: $NAME: shm_s scalar enumeration returned 0 fields (parser broken?)" >&2
fi

# Step 2: narrow to members that have a counter write site.
# Recognises all nine write spellings via shm_write_pat().
# $CFILES_NORM (continuation-joined) is used so that two-line writes
#   __atomic_fetch_add(
#           &shm->field, ...
# are presented as a single line and matched by shm_write_pat().
# $HFILES_NORM is also scanned so that a field written only in an
# inline header helper is not missing from the population.
while IFS= read -r shm_field; do
	if grep -qE "$(shm_write_pat "$shm_field")" \
		   "$CFILES_NORM" "$HFILES_NORM" 2>/dev/null; then
		echo "$shm_field"
	fi
done < "$SHM_SCALARS" | sort -u > "$SHM_WRITTEN"

shm_written_count="$(wc -l < "$SHM_WRITTEN")"
if [ "$shm_written_count" -eq 0 ]; then
	echo "WARN: $NAME: shm_s written-scalar population is 0 (write-site grep broken?)" >&2
fi

# Denominator sanity: if the population is less than half the total
# scalar count the write-spelling set is probably missing a form.
# The 5/37 situation before the SHM_WRITE_PAT unification would have
# triggered this — emit WARN so the mismatch is visible in CI instead
# of reading silently as green coverage.
if [ "$shm_scalar_count" -gt 0 ] && \
		[ "$((shm_written_count * 2))" -lt "$shm_scalar_count" ]; then
	echo "WARN: $NAME: only $shm_written_count of $shm_scalar_count shm_s scalars have known write sites (check SHM_WRITE_PAT coverage)" >&2
fi

# Step 3: find members with a non-write, non-comment read in the tree.
# A line counts as a read if:
#   - it contains shm->X (as a whole word), AND
#   - it is not a write (any of the nine spellings in shm_write_pat(), OR
#     a simple / compound assignment: =[^=] *=, /=, <<=, >>=, &=, |=, ^=), AND
#   - it is not a comment line (first non-space is * or //).
# shm_write_pat() is used here for the same nine spellings as Step 2 so
# the two stages share one canonical write-form definition.
# $HFILES_NORM (continuation-joined header stream) is also scanned so
# that inline-header reads (e.g. in include/shm.h) are not invisible to
# this pass.  Using the joined form ensures a read split across two
# header lines is not misclassified by the write-exclusion filter.
while IFS= read -r shm_field; do
	if { grep -hE "\bshm->$shm_field\b" "$CFILES_NORM" 2>/dev/null; \
	     grep -hE "\bshm->$shm_field\b" "$HFILES_NORM" 2>/dev/null; } | \
	   grep -vE '^[[:space:]]*([*/]|//)' | \
	   grep -qvE "$(shm_write_pat "$shm_field")|\bshm->$shm_field[[:space:]]*(=[^=]|\*=|/=|<<=|>>=|&=|\|=|\^=)"; then
		echo "$shm_field"
	fi
done < "$SHM_WRITTEN" | sort -u > "$SHM_READ"

comm -23 "$SHM_WRITTEN" "$SHM_READ" > "$SHM_UNREACHED"

# Allowlist for shm_s scalar counters with write sites.
#
# Operational internal counters (written atomically, read back for
# protocol decisions, but not surfaced in the operator report):
#   running_childs       -- spawn-quorum tracker; read by pids.c for
#                           child-count checks; not a reportable metric.
#   sibling_freeze_gen   -- freeze-epoch sequencer; read by the sibling
#                           freeze sweep in child.c; not a metric.
#   syscalls32_attempted -- biarch probe denominator; read in
#                           syscall-exec.c to gate 32-bit probing;
#                           not surfaced in periodic output.
#   plateau_intervention_rotation_counter -- monotonic per-intervention
#                           rotation sequencer; consumed via the return
#                           value of __atomic_fetch_add (stored in the
#                           local `rot`), not by reading
#                           shm->plateau_intervention_rotation_counter
#                           on any render path.  Newly visible as written
#                           after the multiline-write fix (the write was
#                           a two-line __atomic_fetch_add / &shm->field
#                           split that the old line-based scanner missed).
SHM_ALLOWLIST=(
	running_childs
	sibling_freeze_gen
	syscalls32_attempted
	plateau_intervention_rotation_counter
)
printf '%s\n' "${SHM_ALLOWLIST[@]}" | sort -u > "$TMP/shm_allow"
comm -23 "$SHM_UNREACHED" "$TMP/shm_allow" > "$SHM_UNALLOWED"
shm_allow_count="$(comm -12 "$SHM_WRITTEN" "$TMP/shm_allow" | wc -l)"

# Vacuous-pass guard: if every written field is on the allowlist the gate
# can never FAIL regardless of what is added to shm_s in future.  Emit a
# WARN so the condition is visible in CI output without blocking green.
if [ "$shm_written_count" -gt 0 ] && [ ! -s "$SHM_UNALLOWED" ] && \
	   [ "$shm_allow_count" -eq "$shm_written_count" ]; then
	echo "WARN: $NAME: shm_s pass is currently vacuous — all $shm_written_count written field(s) are allowlisted; gate cannot fail" >&2
fi

if [ -s "$SHM_UNALLOWED" ]; then
	echo "FAIL: $NAME: shm_s scalar counters with write sites but no rendered read and no allowlist entry:" >&2
	sed 's/^/  /' "$SHM_UNALLOWED" >&2
	echo "" >&2
	echo "Either add a render path (stat_row / periodic print / JSON emit" >&2
	echo "referencing shm->X on an emit path) or add to the shm_s allowlist" >&2
	echo "in $0 with an explanatory comment." >&2
	exit 1
fi

echo "PASS: $NAME: $shm_written_count shm_s written scalar(s) checked ($shm_allow_count allowlisted, $((shm_written_count - shm_allow_count)) verified read)"

# Self-test: verify the write-exclusion filter (shm_write_pat + extra
# assignment operators) correctly blocks every write spelling and lets
# no write line slip through as a false read.  All six lines below are
# writes; the combined pipeline must produce zero non-write output
# (i.e. grep -qv must exit non-zero — every line IS excluded).
#   1. tab-indented simple assignment  shm->foo = 0;
#   2. __atomic_add_fetch
#   3. __atomic_fetch_add
#   4. __atomic_store_n              (new spelling — Hole 2 regression test)
#   5. __atomic_compare_exchange_n   (new spelling)
#   6. __atomic_fetch_sub            (new spelling)
_fix_field="foo"
_fix_file="$TMP/fix_fixture"
printf '\tshm->%s = 0;\n\t__atomic_add_fetch(&shm->%s, 1, __ATOMIC_RELAXED);\n\t__atomic_fetch_add(&shm->%s, 1, __ATOMIC_RELAXED);\n\t__atomic_store_n(&shm->%s, 0, __ATOMIC_RELAXED);\n\t__atomic_compare_exchange_n(&shm->%s, &old, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);\n\t__atomic_fetch_sub(&shm->%s, 1, __ATOMIC_RELAXED);\n' \
	"$_fix_field" "$_fix_field" "$_fix_field" "$_fix_field" "$_fix_field" "$_fix_field" > "$_fix_file"
if grep -hE "\bshm->$_fix_field\b" "$_fix_file" | \
   grep -vE '^[[:space:]]*([*/]|//)' | \
   grep -qvE "$(shm_write_pat "$_fix_field")|\bshm->$_fix_field[[:space:]]*(=[^=]|\*=|/=|<<=|>>=|&=|\|=|\^=)"; then
	fail "self-test: a write line was misclassified as a non-write read (write-filter regex broken)"
fi
echo "PASS: $NAME: self-test: all write spellings correctly excluded from read set"

# Self-test: verify that join_continuations correctly joins the two-line
# __atomic_*( / &shm->... pattern and that the joined line is matched as
# a write by the atomic-write filter.
#
# Fixture lines are copied verbatim from the top-offending source files:
#   childops/mm/uffd-fault-move.c               lines 468-470
#   childops/net/packet-qdisc-bypass-unanchored-l2.c  lines 871-873
#   childops/net/igmp-mld-source-churn.c        lines 205-207
# All three share the two-line form:
#   line N:   __atomic_add_fetch(
#   line N+1: \t\t\t&shm->stats.<sub>.<field>, 1, __ATOMIC_RELAXED);
# Without join_continuations the N+1 line lacks __atomic_*( and passes
# the write filter as a false read; after joining both tokens appear on
# one line and the filter correctly excludes it.
_fix_ml_file="$TMP/fix_multiline_fixture"
{
	# childops/mm/uffd-fault-move.c 468-470
	printf '\t\t__atomic_add_fetch(\n'
	printf '\t\t\t&shm->stats.uffd_fault_move.v1_dontwake_woke_early,\n'
	printf '\t\t\t1, __ATOMIC_RELAXED);\n'
	# childops/net/packet-qdisc-bypass-unanchored-l2.c 871-873
	printf '\t\t__atomic_add_fetch(\n'
	printf '\t\t\t&shm->stats.packet_qdisc_bypass_unanchored_l2.lane_a_sends,\n'
	printf '\t\t\t1, __ATOMIC_RELAXED);\n'
	# childops/net/igmp-mld-source-churn.c 205-207
	printf '\t\t__atomic_add_fetch(\n'
	printf '\t\t\t&shm->stats.igmp_mld_source_churn.igmp_max_msf_raise_fail,\n'
	printf '\t\t\t1, __ATOMIC_RELAXED);\n'
} > "$_fix_ml_file"
# Raw fixture: no line should match atomic_write_pattern AND &shm-> together
# (the __atomic_add_fetch( line has no &shm-> and the &shm->... line has no __atomic_).
if grep -qE "${SHM_WRITE_PAT_ATOMIC}\([[:space:]]*&shm->" "$_fix_ml_file"; then
	fail "self-test: multiline fixture: raw file already has one-line atomic+shm pattern (fixture wrong)"
fi
# After join_continuations: every written occurrence must be matched.
if ! join_continuations < "$_fix_ml_file" | \
   grep -qE "${SHM_WRITE_PAT_ATOMIC}\([[:space:]]*&shm->"; then
	fail "self-test: join_continuations did not expose multiline __atomic_add_fetch( / &shm-> writes"
fi
echo "PASS: $NAME: self-test: multiline atomic write correctly joined and matched by write filter"

# Self-test: verify the write-anchor correctly rejects a read of
# shm->FIELD that appears as a later argument (not the first pointer
# arg) of an atomic intrinsic.  The old loose pattern
# (SHM_WRITE_PAT_ATOMIC.*\bshm->FIELD\b) false-positived on this;
# the tight \([[:space:]]*&shm->FIELD[[:space:]]*[,)] anchor must NOT match.
# Line: __atomic_store_n(&shm->other, shm->foo, __ATOMIC_RELAXED);
# -- foo is the value being stored, i.e. a read, not a write.
_fix_fp_file="$TMP/fix_fp_fixture"
printf '\t__atomic_store_n(&shm->other, shm->%s, __ATOMIC_RELAXED);\n' \
	"$_fix_field" > "$_fix_fp_file"
if grep -hE "\bshm->$_fix_field\b" "$_fix_fp_file" | \
   grep -vE '^[[:space:]]*([*/]|//)' | \
   grep -qE "$(shm_write_pat "$_fix_field")|\bshm->$_fix_field[[:space:]]*(=[^=]|\*=|/=|<<=|>>=|&=|\|=|\^=)"; then
	fail "self-test: a read of shm->$_fix_field as a value argument was misclassified as a write (anchor too loose)"
fi
echo "PASS: $NAME: self-test: second-argument read correctly not classified as a write"

# Self-test: verify join_continuations correctly joins a continuation where the
# opening token has a trailing space before end of line (space-after-paren form):
#   __atomic_fetch_add( 
#       &shm->foo, 1, __ATOMIC_RELAXED);
# The trailing space after `(` must not break the `[^)]*$` anchor.
_fix_sp_file="$TMP/fix_space_paren_fixture"
printf '__atomic_fetch_add( \n\t&shm->foo, 1, __ATOMIC_RELAXED);\n' > "$_fix_sp_file"
_fix_sp_out="$TMP/fix_space_paren_out"
join_continuations < "$_fix_sp_file" > "$_fix_sp_out"
_fix_sp_wc="$(wc -l < "$_fix_sp_out")"
if [ "$_fix_sp_wc" -ne 1 ]; then
	fail "self-test: space-after-paren fixture: expected 1 joined output line, got $_fix_sp_wc"
fi
if ! grep -q '__atomic_fetch_add' "$_fix_sp_out" || ! grep -q '&shm->foo' "$_fix_sp_out"; then
	fail "self-test: space-after-paren fixture: joined line missing expected tokens"
fi
echo "PASS: $NAME: self-test: space-after-paren continuation correctly joined"

# Self-test: verify join_continuations() does NOT overwrite pending when two
# consecutive lines both match the continuation pattern (nested-atomic overwrite bug).
#
# Fixture (four lines):
#   Line 1: __atomic_store_n(&shm->foo,          ← matches pattern → pending = line1
#   Line 2:     __atomic_load_n(&shm->bar,       ← also matches; BUGGY awk overwrites
#   Line 3:         __ATOMIC_RELAXED),           ←   pending with line2, drops line1
#   Line 4:     __ATOMIC_RELAXED)
#
# FIXED awk (pending-check before pattern): line1+line2 joined into one output line;
# lines 3 and 4 pass through → 3 output lines; both atomic keywords present.
# BUGGY awk: line1 silently dropped (pending overwritten), output 2 lines;
# __atomic_store_n (the write site) missing from output.
_fix_ns_file="$TMP/fix_nested_store_fixture"
{
	printf '__atomic_store_n(&shm->foo,\n'
	printf '    __atomic_load_n(&shm->bar,\n'
	printf '        __ATOMIC_RELAXED),\n'
	printf '    __ATOMIC_RELAXED)\n'
} > "$_fix_ns_file"
_fix_ns_out="$TMP/fix_nested_store_out"
join_continuations < "$_fix_ns_file" > "$_fix_ns_out"
# Both atomic keywords must appear (store line must not have been dropped).
if ! grep -q '__atomic_store_n' "$_fix_ns_out"; then
	fail "self-test: nested-store fixture: __atomic_store_n was dropped by join_continuations (consecutive-match overwrite bug)"
fi
if ! grep -q '__atomic_load_n' "$_fix_ns_out"; then
	fail "self-test: nested-store fixture: __atomic_load_n missing from join_continuations output"
fi
# Line count: one 2-line join → 1 line; remaining 2 lines pass through = 3 total.
# Buggy awk drops line1 and joins line2+line3 → 2 lines.
_fix_ns_wc="$(wc -l < "$_fix_ns_out")"
if [ "$_fix_ns_wc" -ne 3 ]; then
	fail "self-test: nested-store fixture: expected 3 output lines from join_continuations, got $_fix_ns_wc (content dropped or rule order wrong)"
fi
echo "PASS: $NAME: self-test: nested-store consecutive-match not overwritten by join_continuations"
exit 0
