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
	done < <(sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' "$BASELINE")
fi

RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE" 2>/dev/null' EXIT

# Walk every .c file under childops/.  For each file that has no
# childop_direct_syscalls_add() call in its own body (comment-stripped),
# scan for raw-syscall invocations.  A non-zero count means the file
# issues syscalls that are not reported into the direct-syscall telemetry
# bucket.
#
# Second pass: even for wired files, scan static void *-returning
# (pthread worker) function bodies.  A worker that issues raw syscalls
# but does not accumulate a tally back into its arg struct is invisible
# to the first pass and is reported as THREAD_UNCOUNTED.  Tally
# accumulation is inferred from: a reference to a struct member whose
# name contains "syscall", "tally", or "count" via ->, or an
# __atomic_add_fetch / __atomic_fetch_add call.  The worker-thread raw-
# syscall set is broader than the main-body set: it includes close, open,
# recv, send, read, and write in addition to the standard set.
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
		in_fn = 0
		brace_depth = 0
		fn_raw_sites = 0
		fn_has_tally = 0
		fn_name = ""
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

		# --- Worker-thread (static void *) function scan ---
		# Detect the start of a static void * function definition.
		if (!in_fn && match(code,
		    /static[[:space:]]+void[[:space:]]*\*[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			in_fn = 1
			brace_depth = 0
			fn_raw_sites = 0
			fn_has_tally = 0
			# Extract the function name.
			tmp = substr(code, RSTART)
			sub(/static[[:space:]]+void[[:space:]]*\*[[:space:]]*/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}

		if (in_fn) {
			# Track brace depth to find function body bounds.
			n = length(code)
			for (j = 1; j <= n; j++) {
				c = substr(code, j, 1)
				if (c == "{") brace_depth++
				else if (c == "}") {
					brace_depth--
					if (brace_depth == 0) {
						if (fn_raw_sites > 0 && !fn_has_tally)
							print "THREAD_UNCOUNTED " file " fn=" fn_name " raw_sites=" fn_raw_sites
						in_fn = 0
						fn_name = ""
					}
				}
			}
			# Broader raw-syscall set for worker bodies: includes
			# close, open, recv, send, read, write in addition to
			# the standard set used for the file-level check.
			tscan = code
			while (match(tscan,
			    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall|close|open|recv|send|read|write)[[:space:]]*\(/)) {
				fn_raw_sites++
				tscan = substr(tscan, RSTART + RLENGTH - 1)
			}
			# Tally-accumulation heuristic: a reference to a struct
			# member containing "syscall", "tally", or "count" via
			# ->, or an __atomic_add_fetch / __atomic_fetch_add call.
			if (!fn_has_tally) {
				if (match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/) ||
				    index(code, "__atomic_add_fetch") ||
				    index(code, "__atomic_fetch_add"))
					fn_has_tally = 1
			}
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
			# Key is bare filename; baseline entry is UNCOUNTED:<file>.
			gf_key="UNCOUNTED:${key}"
			;;
		THREAD_UNCOUNTED)
			# Derive per-function key: file#fn_name so that multiple
			# workers in the same file each get their own baseline slot.
			fn_token="${rest%% *}"
			fn_name="${fn_token#fn=}"
			key="${key}#${fn_name}"
			gf_key="THREAD_UNCOUNTED:${key}"
			;;
		*) continue ;;
	esac
	[ -n "${SEEN_KEY[$key]+x}" ] && continue
	SEEN_KEY["$key"]=1
	if [ -n "${GRANDFATHERED[$gf_key]+x}" ]; then
		:
	else
		new_unbaselined+=("[$kind] $key ($rest)")
	fi
done < "$RESULTS_FILE"

# Stale baseline entries: listed but no longer have uncounted syscall
# sites (wired up or removed).  Advisory, not fatal.
stale_baseline=()
for gf_entry in "${!GRANDFATHERED[@]}"; do
	case "$gf_entry" in
		UNCOUNTED:*)        bare_key="${gf_entry#UNCOUNTED:}" ;;
		THREAD_UNCOUNTED:*) bare_key="${gf_entry#THREAD_UNCOUNTED:}" ;;
		*)                  bare_key="$gf_entry" ;;
	esac
	if [ -z "${SEEN_KEY[$bare_key]+x}" ]; then
		stale_baseline+=("$gf_entry")
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
