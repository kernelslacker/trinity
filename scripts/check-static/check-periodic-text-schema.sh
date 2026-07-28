#!/bin/bash
#
# periodic-text-schema: pin the block-header + counter-name schema of
# the parent-side periodic text surfaces emitted from
# main/loop.c::run_periodic_surfaces() against a golden baseline.
#
# Background: run_periodic_surfaces() orchestrates the six periodic
# text emitters -- counter-rates, childop-split, cost-pool,
# top-syscalls, vma, plus the strategy-topn block invoked from the
# strategy-summary path -- each of which writes a human-readable line
# family via stats_log_write() / output().  These text lines are not
# JSON; the stats-json-schema check next to this one pins the machine
# surface, not the periodic-text surface.  Downstream operator tooling
# (dashboards, log scrapers, triage grep muscle memory) keys off the
# block headers ("Periodic counter rates over last", "cost-pool
# active:", "childop_split:", "Top %u syscalls by new edges in last",
# "[main] VMAs:", ...) and off the row-name literals inside the
# counter-rates table (shared_buffer_redirected, deferred_free_reject,
# frontier_live_would_skip, ...).  A rename, removal, or reordering
# silently reshapes the periodic surface with no compile or test
# failure -- readers just stop matching or start matching the wrong
# line.
#
# The check has two halves, matching the two ways a periodic-text
# emitter can drift:
#
#   (1) BLOCK ORDER + HEADERS.  For each stats/periodic/*.c file in
#       the emission order run_periodic_surfaces() dispatches (with
#       strategy-topn appended), extract the leading token of every
#       stats_log_write() / output() format string -- everything up to
#       the first '%' or closing '"' -- in source-line order.  This
#       captures both the block-header shape ("cost-pool active:",
#       "Top %u syscalls by ...") and the per-row lead-ins the
#       downstream tooling greps for.  Source-line order maps
#       one-to-one to emission order inside each block because each
#       emitter is a straight-line function that writes top-to-bottom.
#
#   (2) COUNTER-RATE NAMES.  Extract the { "name", offsetof(...) }
#       entries from the periodic_counter_rates[] table in
#       counter-rates.c as a sorted-unique set.  The table is a set,
#       not a sequence -- the dump loop walks it in array order but
#       skips zero-delta rows, so the on-wire order is data-dependent;
#       what matters for schema drift is the set membership.
#
# The active-syscall bounds, picker-context folding, and childop
# recency semantics that the emitters preserve at runtime are pinned
# structurally by the block-header extraction: the two "top %u by ..."
# headers for the bounded top-syscalls block, the picker-context sum
# rendered as a per-nr recent_weight column, and the childop_split
# row-name all appear verbatim in the baseline and would drift the
# check if the underlying semantics changed shape.
#
# To regenerate after an intentional schema change:
#   scripts/check-static/check-periodic-text-schema.sh --regen
# then review the resulting periodic-text-schema.baseline diff and
# commit it alongside the schema change.

set -u

NAME="periodic-text-schema"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SRCDIR="$ROOT/stats/periodic"
BASELINE="$ROOT/scripts/check-static/periodic-text-schema.baseline"

# File dispatch order matches main/loop.c::run_periodic_surfaces() plus
# strategy-topn appended (invoked from dump_stats_strategy_summary(),
# not run_periodic_surfaces itself, but part of the same periodic-text
# surface family the task groups together).
FILES=(
	counter-rates.c
	childop-split.c
	cost-pool.c
	top-syscalls.c
	vma.c
	strategy-topn.c
)

fail() {
	echo "FAIL: $NAME: $1" >&2
	exit 1
}

[ -d "$SRCDIR" ] || fail "cannot read $SRCDIR"

for f in "${FILES[@]}"; do
	[ -r "$SRCDIR/$f" ] || fail "missing periodic source $SRCDIR/$f -- update FILES list"
done

# Extract block-header + row-lead tokens from an emitter file.  Match
# every stats_log_write(...) or output(N, ...) call, walk forward to
# the terminating ");" so multi-line format strings and adjacent
# string-literal concatenation are captured, strip format specifiers
# (%d %lu %-24s %8lu etc.) so only the human-readable lead-in text
# survives, then collapse whitespace and emit one line per call.
# Source-line order is preserved to capture emission order within
# each block.
extract_headers() {
	local f="$1"
	awk '
		function trim(s) {
			sub(/^[[:space:]]+/, "", s)
			sub(/[[:space:]]+$/, "", s)
			return s
		}
		function collapse(s) {
			# Concatenate adjacent quoted literals: any run of
			# closing-quote / whitespace / opening-quote between
			# two literal chunks folds away.
			gsub(/"[[:space:]]*"/, "", s)
			# Strip escape sequences that are not schema signal.
			gsub(/\\n/, " ", s)
			gsub(/\\t/, " ", s)
			gsub(/\\"/, "", s)
			# Strip printf conversion specifiers: optional flags,
			# width (including "*"), optional precision, optional
			# length modifier, then the conversion char.  Matches
			# %d %lu %-32s %8lu %10s %ld %.3f %04x and the %%
			# literal-percent escape.
			gsub(/%[-+#0 ]*(\*|[0-9]+)?(\.(\*|[0-9]+))?(hh|h|ll|l|j|z|t|L)?[diouxXeEfgGaAcspn%]/, "", s)
			# Collapse repeated whitespace.
			gsub(/[[:space:]]+/, " ", s)
			return trim(s)
		}
		function grab_literal(buf,    out, q, e, rest) {
			# Concatenate every top-level string literal in buf
			# (which spans one full stats_log_write(...) call).
			out = ""
			rest = buf
			while ((q = index(rest, "\"")) > 0) {
				rest = substr(rest, q + 1)
				e = 0
				# Find closing " that is not preceded by an
				# odd run of backslashes.
				i = 1
				while (i <= length(rest)) {
					c = substr(rest, i, 1)
					if (c == "\\") { i += 2; continue }
					if (c == "\"") { e = i; break }
					i++
				}
				if (e == 0) break
				out = out substr(rest, 1, e - 1)
				rest = substr(rest, e + 1)
				# Bail on the format-arg tail so we do not
				# pick up quoted column-header strings after
				# a comma.  The extract_headers contract is
				# "first format string", not "every literal
				# in the call".
				if (match(rest, /^[[:space:]]*,/)) break
			}
			return out
		}
		{
			line = $0
			# Strip line comments so a trailing // ... does not
			# swallow the ");" terminator on unrelated lines.
			sub(/\/\/.*$/, "", line)
			if (accumulating) {
				buf = buf " " line
				if (index(line, ");") > 0) {
					lit = grab_literal(buf)
					sig = collapse(lit)
					if (length(sig) > 0) print sig
					accumulating = 0
					buf = ""
				}
				next
			}
			if (match(line, /stats_log_write[[:space:]]*\(/) ||
			    match(line, /output[[:space:]]*\([[:space:]]*[0-9]+[[:space:]]*,/)) {
				buf = substr(line, RSTART)
				if (index(buf, ");") > 0) {
					lit = grab_literal(buf)
					sig = collapse(lit)
					if (length(sig) > 0) print sig
				} else {
					accumulating = 1
				}
			}
		}
	' "$f"
}

# Extract periodic_counter_rates[] row names from counter-rates.c as
# a sorted-unique set.  Table order is a data-dependent walk (dump
# loop skips zero-delta rows), so set membership is what drifts.
extract_counter_names() {
	grep -oE '\{[[:space:]]*"[a-z_][a-z0-9_]*",' "$SRCDIR/counter-rates.c" \
		| sed -E 's/^\{[[:space:]]*"//; s/",$//' \
		| sort -u
}

emit_schema() {
	local f
	for f in "${FILES[@]}"; do
		echo "=== ${f%.c} ==="
		extract_headers "$SRCDIR/$f"
	done
	echo "=== counter-rate-names ==="
	extract_counter_names
}

current=$(emit_schema)

[ -n "$current" ] || fail "schema extraction produced no output -- extractor is stale"

if [ "${1:-}" = "--regen" ]; then
	{
		cat <<'EOF'
# periodic-text-schema.baseline
#
# Block-header + counter-name schema pinned from
# stats/periodic/*.c.  Regenerate with
#   scripts/check-static/check-periodic-text-schema.sh --regen
# after an intentional schema change; commit the diff alongside the
# code change with a Summary line explaining the drift.
#
# Section markers ("=== name ===") demarcate each source file in
# main/loop.c::run_periodic_surfaces() dispatch order, plus a
# trailing counter-rate-names set for the periodic_counter_rates[]
# table in counter-rates.c.  Lines beginning with '#' and blank
# lines are ignored on compare.
EOF
		printf '%s\n' "$current"
	} > "$BASELINE"
	line_count=$(printf '%s\n' "$current" | grep -cv '^$')
	echo "REGEN: $NAME: wrote $line_count schema lines to ${BASELINE#"$ROOT"/}"
	exit 0
fi

[ -r "$BASELINE" ] || fail "baseline missing at ${BASELINE#"$ROOT"/} -- run with --regen to seed"

baseline=$(grep -Ev '^\s*(#|$)' "$BASELINE")

if [ "$current" != "$baseline" ]; then
	{
		echo "FAIL: $NAME: periodic-text schema drift vs baseline (${BASELINE#"$ROOT"/})"
		diff -u <(printf '%s\n' "$baseline") <(printf '%s\n' "$current") \
			| sed -e 's/^/  /' >&2
		echo "  If the schema change is intentional, run"
		echo "    scripts/check-static/check-periodic-text-schema.sh --regen"
		echo "  and commit the updated baseline alongside the code change."
	} >&2
	exit 1
fi

line_count=$(printf '%s\n' "$current" | grep -cv '^$')
echo "PASS: $NAME: $line_count schema lines pinned across ${#FILES[@]} emitter files"
exit 0
