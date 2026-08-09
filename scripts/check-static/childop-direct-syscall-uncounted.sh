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
#   trinity_raw_syscall, trinity_cmp_syscall, raw_<name> (file-local
#   syscall wrappers), socket, sendmsg, sendto, setsockopt, mmap, syscall
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
# Second pass: even for wired files, scan worker function bodies.
# Two worker shapes are detected:
#
#   Pthread workers (static void * return): reported as THREAD_UNCOUNTED.
#   Fork workers (static void return, or __attribute__((noreturn)) static void):
#     reported as FORK_UNCOUNTED.  The function is classified as a fork-child
#     body when ANY of the following terminators appears inside it (any one is
#     sufficient; _exit() alone is too narrow -- some workers use raw syscalls
#     or the POSIX _Exit() form):
#       _exit(              -- traditional POSIX
#       _Exit(              -- POSIX capital-E form (C99/C11)
#       syscall(__NR_exit   -- raw kernel exit via glibc syscall()
#       trinity_raw_syscall(__NR_exit  -- raw exit via trinity's wrapper
#       syscall(__NR_exit_group       -- exit_group raw form
#       trinity_raw_syscall(__NR_exit_group
#       __attribute__.*noreturn        -- function is noreturn (unconditional)
#     Concrete motivating case: af_unix_sibling_main() in
#     childops/net/af-unix-scm-rights-gc.c terminates via
#     syscall(__NR_exit, 0) with no bare _exit() token in the file.
#
# A worker is flagged only when it both (a) has raw-syscall sites and
# (b) does not accumulate those syscalls back via a struct member whose
# name contains "syscall", "tally", or "count" accessed through ->.
# The worker raw-syscall set is broader than the main-body set: it
# includes close, open, recv, send, read, and write in addition to
# the standard set.
#
# FORK_UNCOUNTED entries are buffered and emitted only for wired files
# (where the file-level UNCOUNTED check would otherwise pass silently);
# for unwired files the file-level UNCOUNTED entry covers fork workers.
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
		is_fork_fn = 0
		fork_fn_exit_seen = 0
		fork_fn_has_fork = 0
		brace_depth = 0
		fn_raw_sites = 0
		fn_tally_count = 0
		fn_name = ""
		fork_uncounted_n = 0
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
		    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])raw_[a-z_]+[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall)[[:space:]]*\(/)) {
			raw_sites++
			scan = substr(scan, RSTART + RLENGTH - 1)
		}

		# --- Worker function scans ---
		#
		# Pthread workers: static void * return.
		if (!in_fn && match(code,
		    /static[[:space:]]+void[[:space:]]*\*[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			in_fn = 1
			is_fork_fn = 0
			fork_fn_exit_seen = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			# Extract the function name.
			tmp = substr(code, RSTART)
			sub(/static[[:space:]]+void[[:space:]]*\*[[:space:]]*/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}
		# Fork workers: static void return (not void *).  Three header shapes
		# are matched:
		#   (a) plain:    static void foo(
		#   (b) noreturn before: __attribute__((noreturn)) static void foo(
		#   (c) noreturn after:  static __attribute__((noreturn)) void foo(
		# The void[[:space:]]+ guard (at least one space, then a letter) is
		# mutually exclusive with void[[:space:]]*\* above: a void* return
		# always has * before the name.  When __attribute__((noreturn)) appears
		# on its own line before the static void line, shape (a) catches it on
		# the following line.
		if (!in_fn && match(code,
		    /(__attribute__[[:space:]]*\(\([^)]*noreturn[^)]*\)\)[[:space:]]+static[[:space:]]+void|static[[:space:]]+(__attribute__[[:space:]]*\(\([^)]*noreturn[^)]*\)\)[[:space:]]+)?void)[[:space:]]+[a-zA-Z][a-zA-Z0-9_]*[[:space:]]*\(/)) {
			in_fn = 1
			is_fork_fn = 1
			fork_fn_exit_seen = 0
			fork_fn_has_fork = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			# Strip any leading __attribute__ and/or static void prefix
			# before extracting the function name.
			sub(/.*void[[:space:]]+/, "", tmp)
			match(tmp, /^[a-zA-Z][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}
		# Childop entry functions: bool NAME(struct childdata *child).
		# These are the primary per-childop entry points; they run in the
		# child context and must account for every raw syscall they issue.
		# No fork/exit detection is needed -- they return normally.
		if (!in_fn && match(code,
		    /bool[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*struct[[:space:]]+childdata[[:space:]]*\*/)) {
			in_fn = 1
			is_fork_fn = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			sub(/bool[[:space:]]+/, "", tmp)
			match(tmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)
			fn_name = substr(tmp, RSTART, RLENGTH)
		}
		# Clone body (_in_ns pattern): static int NAME(void *arg).
		# Used for clone(2) grandchild bodies that must return int.  The
		# int return type excluded them from the void/void* patterns above
		# by construction; they are treated as thread workers here.
		if (!in_fn && match(code,
		    /static[[:space:]]+int[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*void[[:space:]]*\*[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\)/)) {
			in_fn = 1
			is_fork_fn = 0
			brace_depth = 0
			fn_raw_sites = 0
			fn_tally_count = 0
			delete fn_acc_incr
			tmp = substr(code, RSTART)
			sub(/static[[:space:]]+int[[:space:]]+/, "", tmp)
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
						if (is_fork_fn) {
							# Fork worker: only flag if _exit() was
							# seen (confirms fork-child body) AND the
							# function does not call fork() itself
							# (which would make it a parent wrapper
							# with an inline child branch, not a pure
							# fork-child body).  Buffer for END.
							if (fork_fn_exit_seen && !fork_fn_has_fork && fn_raw_sites > 0 && fn_tally_count < fn_raw_sites)
								fork_uncounted[fork_uncounted_n++] = \
									"FORK_UNCOUNTED " file " fn=" fn_name " raw_sites=" fn_raw_sites
							is_fork_fn = 0
						} else {
							if (fn_raw_sites > 0 && fn_tally_count < fn_raw_sites)
								print "THREAD_UNCOUNTED " file " fn=" fn_name " raw_sites=" fn_raw_sites
						}
						in_fn = 0
						fn_name = ""
						delete fn_acc_incr
					}
				}
			}
			# Broader raw-syscall set for worker bodies: includes
			# close, open, recv, send, read, write in addition to
			# the standard set used for the file-level check.
			# Exclude fork-child terminators: syscall(__NR_exit[...]) forms
			# are the termination mechanism, not fuzzed-work syscalls that
			# belong in the direct-call tally.  Replace the syscall( token
			# before scanning so the pattern below cannot match it.
			tscan = code
			gsub(/syscall[[:space:]]*\([[:space:]]*__NR_exit/, "SYSCALL_EXIT", tscan)
			while (match(tscan,
			    /trinity_raw_syscall[[:space:]]*\(|trinity_cmp_syscall[[:space:]]*\(|(^|[^a-zA-Z0-9_])raw_[a-z_]+[[:space:]]*\(|(^|[^a-zA-Z0-9_])(socket|sendmsg|sendto|setsockopt|mmap|syscall|close|open|recv|send|read|write)[[:space:]]*\(/)) {
				fn_raw_sites++
				tscan = substr(tscan, RSTART + RLENGTH - 1)
			}
			# Option-b accumulator-increment tracking: scan for <var>++ and
			# <var> += N on plain local scalars (not ->member accesses).
			# Strip pointer-member dereferences first so struct-field
			# increments are not mistaken for local accumulator bumps.
			{
				incr_scan = code
				gsub(/->[a-zA-Z_][a-zA-Z0-9_]*/, "_MEMBR_", incr_scan)
				tmp2 = incr_scan
				while (match(tmp2, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\+\+/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					sub(/[[:space:]]*\+\+/, "", vn)
					fn_acc_incr[vn] += 1
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
				tmp2 = incr_scan
				while (match(tmp2, /[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\+=[[:space:]]*[0-9]+[UuLl]*/)) {
					vn = substr(tmp2, RSTART, RLENGTH)
					av = vn
					sub(/[[:space:]]*\+=.*$/, "", vn)
					sub(/^[^=]*=[[:space:]]*/, "", av)
					gsub(/[UuLl]/, "", av)
					fn_acc_incr[vn] += av + 0
					tmp2 = substr(tmp2, RSTART + RLENGTH)
				}
			}
			# Fork-child body terminator detection.  ANY one of the following
			# is sufficient to mark this function as a fork-child body:
			#   _exit(              -- traditional POSIX
			#   _Exit(              -- POSIX C99/C11 capital-E form
			#                          (word-boundary: exclude _Exit_foo)
			#   syscall(__NR_exit   -- raw exit via glibc syscall()
			#   trinity_raw_syscall(__NR_exit  -- trinity raw wrapper
			#   syscall(__NR_exit_group       -- exit_group raw form
			#   trinity_raw_syscall(__NR_exit_group
			#   __attribute__.*noreturn -- noreturn annotation within body
			if (is_fork_fn && !fork_fn_exit_seen) {
				if (match(code, /(^|[^a-zA-Z0-9_])_exit[[:space:]]*\(/))
					fork_fn_exit_seen = 1
				else if (match(code, /(^|[^a-zA-Z0-9_])_Exit[[:space:]]*\(/) &&
				         !match(code, /(^|[^a-zA-Z0-9_])_Exit_/))
					fork_fn_exit_seen = 1
				else if (match(code, /syscall[[:space:]]*\([[:space:]]*__NR_exit/))
					fork_fn_exit_seen = 1
				else if (match(code, /trinity_raw_syscall[[:space:]]*\([[:space:]]*__NR_exit/))
					fork_fn_exit_seen = 1
				else if (match(code, /__attribute__[[:space:]]*\(\([^)]*noreturn/))
					fork_fn_exit_seen = 1
			}
			# fork() detection: a function that calls fork() internally is a
			# parent-side wrapper (fork-within-a-function), not a pure
			# fork-child body.  Exclude such functions from FORK_UNCOUNTED.
			if (is_fork_fn && !fork_fn_has_fork &&
			    match(code, /(^|[^a-zA-Z0-9_])fork[[:space:]]*\(/))
				fork_fn_has_fork = 1
			# Tally-accumulation heuristic (magnitude-aware): parse literal
			# addends where possible rather than counting +1 per tally line.
			#
			#   childop_direct_syscalls_add(op, N):
			#     N is a numeric literal (digits + optional UL/U/ULL suffix)
			#       -> add N to fn_tally_count
			#     N contains any identifier (runtime accumulator or a mixed
			#       expression such as 1UL + write_calls + 1UL)
			#       -> fully accounted (fn_tally_count = large sentinel):
			#          a runtime sum cannot be statically verified
			#     Second arg absent on this line (multi-line call)
			#       -> conservative +1 fallback
			#
			#   __atomic_fetch_add / __atomic_add_fetch on a ->...count/
			#   tally/syscall member with literal N -> add N to fn_tally_count;
			#   non-literal N -> conservative +1 (per-site increment).
			#
			#   Other ->...count/tally/syscall patterns: +1 (unchanged).
			if (index(code, "childop_direct_syscalls_add(") > 0) {
				tline = code
				sub(/.*childop_direct_syscalls_add\([^,]*,/, "", tline)
				if (index(tline, ")") > 0) {
					sub(/\).*$/, "", tline)
					sub(/^[ \t]+/, "", tline)
					sub(/[ \t]+$/, "", tline)
					if (tline ~ /^[0-9]+[UuLl]*$/) {
						fn_tally_count += tline + 0
					} else if (length(tline) > 0) {
						# Runtime accumulator (option b): parse the second
						# arg as a sum of literal addends and identifier
						# addends.  For each identifier look up its tracked
						# ++ / += increment count within this function body.
						# The old sentinel fn_tally_count = fn_raw_sites was
						# always equal, making the < test always false --
						# tail-publish functions whose accumulator did not
						# cover every raw-syscall site were invisible to the
						# gate.  Mixed expressions like "1UL + write_calls +
						# 1UL" parse as literal(1) + incr_count(write_calls)
						# + literal(1), correctly matching fn_raw_sites.
						{
							mixed_sum = 0
							etmp = tline
							while (length(etmp) > 0) {
								if (match(etmp, /^[0-9]+[UuLl]*/)) {
									mixed_sum += substr(etmp, RSTART, RLENGTH) + 0
									etmp = substr(etmp, RSTART + RLENGTH)
								} else if (match(etmp, /^[a-zA-Z_][a-zA-Z0-9_]*/)) {
									vn = substr(etmp, RSTART, RLENGTH)
									if (vn in fn_acc_incr)
										mixed_sum += fn_acc_incr[vn]
									etmp = substr(etmp, RSTART + RLENGTH)
								} else {
									etmp = substr(etmp, 2)
								}
							}
							fn_tally_count += mixed_sum
						}
					} else {
						fn_tally_count++
					}
				} else {
					# Second arg on next line: conservative +1
					fn_tally_count++
				}
			} else if (match(code, /__atomic_(fetch_add|add_fetch)[[:space:]]*\(/) &&
			           match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) {
				tline = code
				sub(/.*__atomic_(fetch_add|add_fetch)[[:space:]]*\([^,]*,/, "", tline)
				sub(/,.*$/, "", tline)
				sub(/^[ \t]+/, "", tline)
				sub(/[ \t]+$/, "", tline)
				if (tline ~ /^[0-9]+[UuLl]*$/) {
					fn_tally_count += tline + 0
				} else {
					# Non-literal per-site increment: conservative +1
					fn_tally_count++
				}
			} else if (match(code, /->[ \t]*[a-zA-Z_0-9]*(syscall|tally|count)[a-zA-Z_0-9]*/)) {
				fn_tally_count++
			}
		}
	}
	END {
		if (!wired && raw_sites > 0)
			print "UNCOUNTED " file " raw_sites=" raw_sites
		# Fork-worker findings are only meaningful for wired files:
		# unwired files are already covered by the UNCOUNTED emit above.
		if (wired) {
			for (i = 0; i < fork_uncounted_n; i++)
				print fork_uncounted[i]
		}
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
		FORK_UNCOUNTED)
			# Same key structure as THREAD_UNCOUNTED: file#fn_name.
			fn_token="${rest%% *}"
			fn_name="${fn_token#fn=}"
			key="${key}#${fn_name}"
			gf_key="FORK_UNCOUNTED:${key}"
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
# sites (wired up or removed).  Fatal: exits 1 to enforce baseline hygiene.
stale_baseline=()
for gf_entry in "${!GRANDFATHERED[@]}"; do
	case "$gf_entry" in
		UNCOUNTED:*)        bare_key="${gf_entry#UNCOUNTED:}" ;;
		THREAD_UNCOUNTED:*) bare_key="${gf_entry#THREAD_UNCOUNTED:}" ;;
		FORK_UNCOUNTED:*)   bare_key="${gf_entry#FORK_UNCOUNTED:}" ;;
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
		echo "  ${#stale_baseline[@]} baseline entry/entries no longer"
		echo "  have uncounted raw-syscall sites (stale entries must be pruned):"
		for e in "${stale_baseline[@]}"; do echo "    $e"; done
		echo "  fix: remove the listed entries from"
		echo "       scripts/check-static/childop-direct-syscall-uncounted.baseline"
	} >&2
	echo "FAIL: $NAME: ${#stale_baseline[@]} stale baseline entry/entries"
	exit 1
fi

if [ "${#new_unbaselined[@]}" -gt 0 ]; then
	echo "FAIL: $NAME: ${#new_unbaselined[@]} file(s) with uncounted direct syscalls"
	exit 1
fi

COUNT_BASELINE="$ROOT/scripts/check-static/childop-direct-syscall-uncounted.count.baseline"
frozen=$(cat "$COUNT_BASELINE" 2>/dev/null | tr -d '[:space:]')
if [ -z "$frozen" ] || ! [ "$frozen" -ge 0 ] 2>/dev/null; then
	echo "FAIL: $NAME: cannot read frozen ceiling from $COUNT_BASELINE" >&2
	exit 1
fi

total=${#SEEN_KEY[@]}

if [ "$total" -gt "$frozen" ]; then
	echo "FAIL: uncounted worker count regressed: $total > frozen ceiling $frozen"
	exit 1
fi

echo "PASS: $NAME (uncounted=$total, ceiling=$frozen)"
exit 0
