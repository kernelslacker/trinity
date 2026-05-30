#!/bin/bash
#
# fd-event-close-direct: every producer of FD_EVENT_CLOSE outside
# fd-event.c must go through the canonical close helper
# (notify_child_fd_closed[_range]()).
#
# fd-event.c owns the close-semantic invariants of FD_EVENT_CLOSE:
# the producing child publishes the close to the parent, evicts the
# local fd_hash[] snapshot, and sentinels-out the live_fds ring slot,
# and the parent's drain runs remove_object_by_fd() which retires the
# fd and drops the per-provider outstanding-fd refcount.  Emitting
# the event directly to signal something that is NOT a child-side
# close (parent-context eviction of a foreign fd, stale-slot reuse
# where the fd was reused under us) corrupts that contract: the
# parent runs the close handler on still-live state, or the producer
# skips the local bookkeeping the helper would have done.
#
# Heuristic: every reference to the FD_EVENT_CLOSE enum token in a
# .c file other than fd-event.c is classified.  Switch-case consumers
# (`case FD_EVENT_CLOSE:`) are pure event-dequeue sites and are not
# flagged.  Comment text is stripped before classification.  Anything
# left is a producer, reported as `file:funcname` unless listed in
# the baseline.
#
# A baseline of grandfathered semantic offenders lives alongside this
# script as fd-event-close-direct.baseline (one `file:funcname` per
# line).  The baseline should shrink over time, never grow.

set -u

NAME="fd-event-close-direct"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/fd-event-close-direct.baseline"
CANONICAL="fd-event.c"

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

# Walk every .c file in the repo that mentions FD_EVENT_CLOSE.  The
# canonical producer (fd-event.c) is skipped wholesale; everything
# else is parsed.  Headers are skipped: the enum definition lives in
# include/fd-event.h and is not a producer.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"
	[ "$rel" = "$CANONICAL" ] && continue

	awk -v file="$rel" '
	function strip_comments(s,    idx, tail, cidx) {
		# Continuation of a block comment from a previous line.
		if (in_block) {
			idx = index(s, "*/")
			if (idx == 0) return ""
			s = substr(s, idx + 2)
			in_block = 0
		}
		# Inline block comments on this line.  Strip one at a time;
		# a comment that opens but does not close sets in_block and
		# truncates the rest of the line.
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
	BEGIN {
		in_block = 0
		cur_func = ""
		pending = ""
	}
	{
		raw = $0
		code = strip_comments(raw)

		# Function-definition tracker.  Trinity convention: the
		# definition opener is a column-0 line of the form
		# `[storage] TYPE [...] IDENT(`, followed by `{` at
		# column 1 on a subsequent line.  Snapshot the last
		# col-0 line that contains `IDENT(`; promote it to
		# cur_func when a column-0 `{` arrives.  Function calls
		# never sit at column 0 in normal Trinity style, so the
		# false-positive rate is low.
		if (raw ~ /^[A-Za-z_]/ && match(raw, /([A-Za-z_][A-Za-z0-9_]+)[[:space:]]*\(/, m)) {
			pending = m[1]
		}
		if (raw ~ /^\{/ && pending != "") {
			cur_func = pending
			pending = ""
		}

		# Pure consumer: switch on a dequeued event tag.  This
		# is the read side of the contract and is always legal.
		if (code ~ /case[[:space:]]+FD_EVENT_CLOSE[[:space:]]*:/) next

		if (index(code, "FD_EVENT_CLOSE") > 0) {
			fname = (cur_func == "") ? "<file-scope>" : cur_func
			print "VIOLATION " file ":" fname
		}
	}
	' "$srcfile"
done < <(grep -lr 'FD_EVENT_CLOSE' "$ROOT" --include='*.c' | sort) > "$RESULTS_FILE"

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS=' ' read -r kind key; do
	case "$kind" in
		VIOLATION)
			# Each producer line emits one record; dedup so a
			# baseline entry covers all references inside the
			# same enclosing function.
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

# Stale baseline entries: listed but no longer producing FD_EVENT_CLOSE
# (helper-routed or removed).  Advisory, not fatal.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} site(s) emit FD_EVENT_CLOSE outside fd-event.c without the close helper:"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: route through notify_child_fd_closed() or"
		echo "       notify_child_fd_closed_range() (fd-event.c) -- those"
		echo "       carry the local fd_hash[] / live_fds eviction the"
		echo "       producer must pair with the publish."
		echo "       If the producer is semantically NOT a close (parent-"
		echo "       context eviction, stale-slot reuse) add the entry to"
		echo "       scripts/check-static/fd-event-close-direct.baseline"
		echo "       and plan a follow-up to introduce a distinct event"
		echo "       type rather than re-using CLOSE for non-close shapes."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "        emit FD_EVENT_CLOSE (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} unbaselined direct FD_EVENT_CLOSE producer(s)"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
helper_routed=0   # producers outside fd-event.c that route through
		  # the helper never reference FD_EVENT_CLOSE directly,
		  # so they are not counted here; this metric only
		  # tracks remaining direct producers.
direct=$total
echo "PASS: $NAME (direct=$direct, grandfathered=$baseline_size)"
exit 0
