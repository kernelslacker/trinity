#!/bin/bash
#
# childop-direct-syscall-uncounted: every childop translation unit that
# issues raw syscalls in its own body must call childop_direct_syscalls_add()
# so the direct-syscall telemetry counter stays accurate.
#
# Background: Trinity's per-child syscall accounting has two layers.
#   1. The random_syscall path (child.c) counts every dispatched syscall
#      via the shm->stats.childop.direct_syscalls[op] array, published by
#      child-altop-score.c at the end of each iteration.
#   2. Childops that issue raw syscalls in their own body (socket(),
#      sendmsg(), trinity_raw_syscall(), etc.) must additionally call
#      childop_direct_syscalls_add(op, n) so those calls appear in the
#      same accounting bucket.  The netlink transport (childops-netlink.h)
#      calls childop_direct_syscalls_add() internally at nl_close() for
#      the netlink path, but own-body calls outside the nl_* transport
#      still need a manual publish.
#
# Heuristic: for every childops/*.c (or subdirectory .c) file that does
# not contain a call to childop_direct_syscalls_add(), scan the
# comment-stripped code for raw-syscall invocations from the set:
#   trinity_raw_syscall, trinity_cmp_syscall, socket, sendmsg, sendto,
#   setsockopt, mmap, syscall
# Any such file is classified as an uncounted direct-syscall producer.
# Files in the baseline are grandfathered; anything not listed there
# fails the gate.
#
# Note on nl_*-routed files: childops that open a netlink context with a
# valid caller_op already have their netlink-path syscalls counted by
# nl_close() / childop_direct_syscalls_add().  However, many such files
# also carry own-body socket()/sendmsg()/etc. calls that are NOT proxied
# through the nl_* transport and therefore remain uncounted.  Rather than
# attempt to distinguish "netlink-proxied" from "own-body" calls
# statically (which would require call-graph analysis), this gate flags
# nl_*-routed files too.  Currently-existing nl_*-routed files that have
# not yet been separately wired are grandfathered in the baseline below;
# the baseline should shrink over time, never grow.  (Scoping decision
# for KC review: conservative inclusion — nl_*-routed files in baseline
# rather than nl_* exclusion in the predicate.)
#
# A baseline of grandfathered files lives alongside this script as
# childop-direct-syscall-uncounted.baseline (one relative path per line).
# The baseline should shrink over time, never grow.

set -u

NAME="childop-direct-syscall-uncounted"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/childop-direct-syscall-uncounted.baseline"
CHILDOPS_DIR="$ROOT/childops"

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

# Walk every .c file under childops/.  For each file that has no
# childop_direct_syscalls_add() call in its own body (comment-stripped),
# scan for raw-syscall invocations.  A non-zero count means the file
# issues syscalls that are not reported into the direct-syscall telemetry
# bucket.
while IFS= read -r srcfile; do
	rel="${srcfile#"$ROOT"/}"

	awk -v file="$rel" '
	function strip_comments(s,    idx, tail, cidx) {
		# Continuation of a block comment from a previous line.
		if (in_block) {
			idx = index(s, "*/")
			if (idx == 0) return ""
			s = substr(s, idx + 2)
			in_block = 0
		}
		# Inline block comments on this line.
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
		raw_sites = 0
		wired = 0
	}
	{
		code = strip_comments($0)
		# Correctly-wired check: the file calls
		# childop_direct_syscalls_add() in non-comment code.
		if (!wired && index(code, "childop_direct_syscalls_add") > 0)
			wired = 1
		scan = code
		# Raw-syscall site predicate: call to any of the
		# substantive syscall-invoking functions used in the
		# childops tree.  The word-boundary guard ([^a-zA-Z0-9_]
		# or start-of-code) prevents matching e.g.
		# "setsockopt_helper" or "nl_socket".  The trailing
		# [[:space:]]*\( anchors to a call site rather than a
		# declaration reference.
		while (match(scan,
		    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall)[[:space:]]*\(/)) {
			raw_sites++
			scan = substr(scan, RSTART + RLENGTH - 1)
		}
	}
	END {
		if (!wired && raw_sites > 0)
			print "UNCOUNTED " file " raw_sites=" raw_sites
	}
	' "$srcfile"
done < <(find "$CHILDOPS_DIR" -name '*.c' | LC_ALL=C sort) > "$RESULTS_FILE"

new_unbaselined=()
declare -A SEEN_KEY=()

while IFS=' ' read -r kind key rest; do
	case "$kind" in
		UNCOUNTED)
			[ -n "${SEEN_KEY[$key]+x}" ] && continue
			SEEN_KEY["$key"]=1
			if [ -n "${GRANDFATHERED[$key]+x}" ]; then
				:
			else
				new_unbaselined+=("$key ($rest)")
			fi
			;;
	esac
done < "$RESULTS_FILE"

# Stale baseline entries: listed but no longer have uncounted syscall
# sites (wired up or removed).  Advisory, not fatal.
stale_baseline=()
for entry in "${!GRANDFATHERED[@]}"; do
	if [ -z "${SEEN_KEY[$entry]+x}" ]; then
		stale_baseline+=("$entry")
	fi
done

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	{
		echo "  ${#new_unbaselined[@]} childop file(s) issue raw syscalls"
		echo "  without calling childop_direct_syscalls_add():"
		for e in "${new_unbaselined[@]}"; do echo "    $e"; done
		echo "  fix: add a direct_calls counter, bump it at each raw-syscall"
		echo "       site in the file, and publish at the tail return:"
		echo "         if (valid_op && direct_calls > 0)"
		echo "             childop_direct_syscalls_add(op, direct_calls);"
		echo "       If the file issues syscalls only through the nl_*"
		echo "       transport (nl_open/nl_send_recv/nl_close with a valid"
		echo "       caller_op), nl_close() already calls"
		echo "       childop_direct_syscalls_add() and no additional call"
		echo "       is needed -- but add the file to"
		echo "       scripts/check-static/childop-direct-syscall-uncounted.baseline"
		echo "       so the gate knows it is intentionally netlink-only."
		echo "       The baseline should shrink over time, never grow."
	} >&2
fi

if [ "${#stale_baseline[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "        have uncounted raw-syscall sites (consider pruning):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} file(s) with uncounted direct syscalls"
	exit 1
fi

baseline_size=${#GRANDFATHERED[@]}
total=${#SEEN_KEY[@]}
echo "PASS: $NAME (uncounted=$total, grandfathered=$baseline_size)"
exit 0
