#!/bin/bash
#
# shm-latch-direct: certain `struct shm_s` fields are latches -- the
# write site publishes state to other children that read it through
# `__atomic_load_n(&shm->X, ...)`.  A plain `shm->X = value` from any
# context other than the documented atomic accessor produces a torn
# write under a concurrent reader and silently breaks the publish
# ordering that the load side relies on.
#
# Watch list (each verified RELAXED/RELEASE-stored only today, every
# read already an ACQUIRE/RELAXED atomic load):
#
#   - exit_reason: fleet-wide shutdown signal.  RELAXED stores from
#     the EXIT_NO_SYSCALLS_ENABLED handlers, the panic path, the
#     child watchdog, etc.  Every reader uses __atomic_load_n with
#     RELAXED ordering.  A plain store would race the loaders and
#     can drop the shutdown signal on architectures where the int
#     store is not atomic at the language level.
#
#   - current_strategy: RELEASE-stored by the CAS-winning child at
#     rotation, ACQUIRE-loaded by every picker.  Companion latches
#     (plateau_intervention_mode_current, plateau_anti_prior_*) ride
#     on the same RELEASE -- a plain store here breaks the publish
#     ordering for the whole rotation hand-off, not just this field.
#
#   - current_selection_reason: companion to current_strategy,
#     published at the same rotation boundary.  Read on the hot pick
#     path to gate forced-intervention-only behaviour (anti-prior
#     accept gate, rescue-class amplification).
#
#   - plateau_current_hypothesis: RELAXED-stored by the parent's
#     stats tick, RELAXED-loaded by select_next_strategy() and the
#     children's hot path.  Single-writer-vs-many-readers protocol
#     breaks if the write side becomes a plain store under a
#     concurrent reader.
#
#   - ready, spawn_no_more, postmortem_in_progress: RELEASE-stored
#     by main / postmortem driver, ACQUIRE-loaded by every child on
#     its startup gate (ready) and on the cross-child wait loops
#     (spawn_no_more, postmortem_in_progress).  RELEASE/ACQUIRE
#     pairs the latch write to the bookkeeping the readers consume
#     after they see the flag flip; a plain store breaks the
#     happens-before edge and the readers can observe the flag
#     before the data the publish was meant to make visible.
#
#   - dont_make_it_fail, no_fail_nth, no_pidns, no_private_ns,
#     iouring_enosys, socket_family_chain_unsupported,
#     recipe_disabled[], iouring_recipe_disabled[],
#     sfg_unsupported[]: feature-discovery latches.  First child to
#     observe "kernel can't / won't do this" RELAXED-stores true so
#     siblings stop probing; every reader RELAXED-loads.  A torn
#     load on a fresh child can leave the bit half-flipped: the
#     reader treats the feature as still-supported and re-runs the
#     probe path, burning the syscall budget on a known-dead arm.
#     Array entries share the same protocol -- the per-slot store
#     publishes to all other children's per-slot loads.
#
# Heuristic: every `shm->FIELD` token reference (with FIELD in the
# watch list) outside an `&shm->FIELD` operand is a violation.
# Address-of is the only legal way to feed an `__atomic_*` intrinsic;
# anything else is a direct load or store.  Comments and string
# literals are stripped before classification (the existing
# `outputerr("shm->exit_reason=%d ...", ...)` debug print would
# otherwise false-positive).  Headers are skipped: the struct
# definition itself is not a usage, and the inline accessors in
# include/shm.h already use the `&shm->FIELD` form.
#
# Allowlisted by construction: every access that goes through
# __atomic_load_n / __atomic_store_n / __atomic_fetch_* / __atomic_
# compare_exchange_n unconditionally takes `&shm->FIELD`, so the
# address-of rule lets them through without needing a file-level
# allowlist.
#
# A baseline of grandfathered offenders lives alongside this script
# as shm-latch-direct.baseline (one `file:funcname` per line).  The
# baseline should shrink over time, never grow.

set -u

NAME="shm-latch-direct"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/shm-latch-direct.baseline"

# Watch list.  Pipe-separated for the awk regex; keep this in sync
# with the per-field documentation above.  Add fields conservatively:
# the field's existing write sites must all be __atomic_store_n /
# __atomic_fetch_*, otherwise the very first check run will flip
# legitimate writers into baseline entries.
WATCH="exit_reason|current_strategy|current_selection_reason|plateau_current_hypothesis|ready|spawn_no_more|postmortem_in_progress|dont_make_it_fail|no_fail_nth|no_pidns|no_private_ns|iouring_enosys|socket_family_chain_unsupported|recipe_disabled|iouring_recipe_disabled|sfg_unsupported"

declare -A GRANDFATHERED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		GRANDFATHERED["$entry"]=1
	done < <(sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" 2>/dev/null' EXIT

# Candidate file list: every .c file that mentions `shm->X` for some X
# in the watch set.  Headers are excluded (`--include='*.c'`).
mapfile -t SRCFILES < <(grep -lE "shm->($WATCH)([^a-zA-Z0-9_]|$)" \
		--include='*.c' -r "$ROOT" 2>/dev/null \
	| sort)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "PASS: $NAME (no watched-field references)"
	exit 0
fi

for srcfile in "${SRCFILES[@]}"; do
	rel="${srcfile#"$ROOT"/}"

	awk -v file="$rel" -v watch="$WATCH" '
	function strip_comments(s,    idx, tail, cidx) {
		# Continuation of a block comment from a previous line.
		if (in_block) {
			idx = index(s, "*/")
			if (idx == 0) return ""
			s = substr(s, idx + 2)
			in_block = 0
		}
		# Inline block comments on this line.  Strip one at a
		# time; a comment that opens but does not close sets
		# in_block and truncates the rest of the line.
		while ((idx = index(s, "/*")) > 0) {
			tail = substr(s, idx + 2)
			cidx = index(tail, "*/")
			if (cidx == 0) {
				in_block = 1
				s = substr(s, 1, idx - 1)
				break
			}
			s = substr(s, 1, idx - 1) " " substr(tail, cidx + 2)
		}
		sub(/\/\/.*$/, "", s)
		return s
	}
	function strip_strings(s,    out, i, c, in_str, esc) {
		# Walk character-by-character, dropping anything that
		# sits inside a "..." literal.  Track the backslash flag
		# so an escaped quote (\") inside the literal does not
		# end the string early.  C string concatenation across
		# adjacent literals is irrelevant here -- each segment
		# is its own "..." run.
		out = ""
		in_str = 0
		esc = 0
		for (i = 1; i <= length(s); i++) {
			c = substr(s, i, 1)
			if (in_str) {
				if (esc) {
					esc = 0
				} else if (c == "\\") {
					esc = 1
				} else if (c == "\"") {
					in_str = 0
				}
				continue
			}
			if (c == "\"") {
				in_str = 1
				continue
			}
			out = out c
		}
		return out
	}
	BEGIN {
		in_block = 0
		cur_func = ""
		pending = ""
		# Boundary on the trailing side prevents a prefix-match
		# false positive if anyone later adds e.g.
		# `exit_reason_count` to the struct.
		regex = "shm->(" watch ")([^a-zA-Z0-9_]|$)"
	}
	{
		raw = $0
		code = strip_strings(strip_comments(raw))

		# Function-definition tracker, same shape as the
		# fd-event-close-direct check.  Trinity convention: the
		# definition opener is a column-0 line containing
		# `IDENT(`, followed by `{` at column 1 on a later line.
		if (raw ~ /^[A-Za-z_]/ && match(raw, /([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
			pending = m[1]
		}
		if (raw ~ /^\{/ && pending != "") {
			cur_func = pending
			pending = ""
		}

		# Scan every shm->WATCHED occurrence on the line and
		# classify by the char immediately preceding the match.
		# Whitespace before `shm` is skipped; if the next
		# non-space char is `&` the form is an address-of feeding
		# an __atomic_*() intrinsic -- allow.  Anything else is
		# a direct load or store -- flag.
		scan = code
		while (match(scan, regex)) {
			pos = RSTART
			len = RLENGTH
			j = pos - 1
			while (j >= 1 && substr(scan, j, 1) ~ /[ \t]/)
				j--
			prev = (j >= 1) ? substr(scan, j, 1) : ""
			if (prev != "&") {
				fname = (cur_func == "") ? "<file-scope>" : cur_func
				print "VIOLATION " file ":" fname
			}
			scan = substr(scan, pos + len)
		}
	}
	' "$srcfile"
done > "$RESULTS_FILE"

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS=' ' read -r kind key; do
	case "$kind" in
		VIOLATION)
			# Dedup so a baseline entry covers all references
			# inside the same enclosing function.
			[ -n "${SEEN_KEY[$key]+x}" ] && continue
			SEEN_KEY["$key"]=1
			if [ -n "${GRANDFATHERED[$key]+x}" ]; then
				:
			else
				new_unbaselined+=("$key")
			fi
			;;
	esac
done < "$RESULTS_FILE"

# Stale baseline entries: listed but no longer producing a direct
# access (helper-routed, removed, or accessor switched to atomic).
# Advisory, not fatal.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} site(s) access a watched shm latch"
		echo "  field without going through an __atomic_*() intrinsic:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: wrap the access in the same atomic intrinsic the"
		echo "       canonical writers / readers use, e.g."
		echo "         __atomic_store_n(&shm->X, value, __ATOMIC_RELAXED)"
		echo "         __atomic_load_n(&shm->X, __ATOMIC_RELAXED)"
		echo "       Match the ordering already used at the existing"
		echo "       call sites (grep for the field name).  RELEASE on"
		echo "       the publish side and ACQUIRE on the consume side"
		echo "       for current_strategy; RELAXED for the rest today."
		echo "       If the site is a debug-only print whose torn read"
		echo "       is genuinely tolerable, add the entry to"
		echo "       scripts/check-static/shm-latch-direct.baseline"
		echo "       (the baseline should shrink, never grow)."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "        access a watched shm latch directly (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unbaselined direct shm-latch access(es)"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
echo "PASS: $NAME (direct=$total, grandfathered=$baseline_size)"
exit 0
