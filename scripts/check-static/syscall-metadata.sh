#!/bin/bash
#
# syscall-metadata: best-effort sanity on struct syscallentry definitions.
#
# Today's enforced rule:
#   - For every argument declared as ARG_RANGE in a syscallentry's
#     .argtype = { ... } initializer, the same syscallentry must
#     declare both .arg_params[N].range.low and .arg_params[N].range.hi.
#     A range without bounds is a fuzzer landmine: rand_range() reads
#     uninitialised .low/.hi as zero and silently always returns 0,
#     wiping the entire intended fuzz domain for that argument.
#
# This is the cheapest, most valuable sanity check we can express with
# grep/awk against the current syscallentry layout.  Future invariants
# (ret_objtype <-> rettype, num_args vs argtype slots) can land as
# follow-on checks once the registry refactor exposes them more
# directly.

set -u

NAME="syscall-metadata"
ROOT="${REPO_ROOT:-$(pwd)}"

# Walk every syscallentry initializer in syscalls/*.c.  For each block
# bracketed by `struct syscallentry syscall_<name> = {` ... `};`,
# collect the set of ARG_RANGE argument indices from .argtype and the
# set of indices for which .arg_params[N].range.low and .range.hi are
# declared.  Flag any ARG_RANGE index missing either bound.

problems=$(
	find "$ROOT/syscalls" -name '*.c' -print | sort | while IFS= read -r srcfile; do
		awk -v file="${srcfile#"$ROOT"/}" '
		function flush(   i, idx, missing) {
			for (idx in range_args) {
				missing = ""
				if (!(idx in have_low)) missing = missing " low"
				if (!(idx in have_hi))  missing = missing " hi"
				if (missing != "")
					printf "%s: %s: arg[%d] is ARG_RANGE but missing%s\n",
						file, entry_name, idx, missing
			}
		}
		/^struct syscallentry syscall_[a-zA-Z0-9_]+\s*=\s*\{/ {
			match($0, /^struct syscallentry syscall_([a-zA-Z0-9_]+)\s*=/, m)
			entry_name = m[1]
			in_entry = 1
			delete range_args
			delete have_low
			delete have_hi
			next
		}
		!in_entry { next }
		# .argtype = { [0] = ARG_RANGE, [2] = ARG_RANGE, ... }
		/\.argtype\s*=/ {
			line = $0
			# Slurp continuation lines until the closing brace of argtype.
			while (line !~ /\}/ && (getline more) > 0) {
				line = line " " more
			}
			n = 0
			# Iterate over every [N] = ARG_TYPE pair.
			rest = line
			while (match(rest, /\[[[:space:]]*([0-9]+)[[:space:]]*\][[:space:]]*=[[:space:]]*([A-Z_][A-Z0-9_]*)/, mm)) {
				if (mm[2] == "ARG_RANGE")
					range_args[mm[1]] = 1
				rest = substr(rest, RSTART + RLENGTH)
			}
			next
		}
		# .arg_params[N].range.low and .arg_params[N].range.hi can
		# appear multiple times per line, so scan the whole line for
		# every occurrence rather than matching once.
		{
			rest = $0
			while (match(rest, /\.arg_params\[[[:space:]]*([0-9]+)[[:space:]]*\]\.range\.low[[:space:]]*=/, m)) {
				have_low[m[1]] = 1
				rest = substr(rest, RSTART + RLENGTH)
			}
			rest = $0
			while (match(rest, /\.arg_params\[[[:space:]]*([0-9]+)[[:space:]]*\]\.range\.hi[[:space:]]*=/, m)) {
				have_hi[m[1]] = 1
				rest = substr(rest, RSTART + RLENGTH)
			}
		}
		# End of this syscallentry struct.
		/^\};/ && in_entry {
			flush()
			in_entry = 0
		}
		END {
			if (in_entry) flush()
		}
		' "$srcfile"
	done
)

if [ -n "$problems" ]; then
	echo "FAIL: $NAME: ARG_RANGE without matching bounds"
	echo "$problems" | sed 's/^/  /' >&2
	exit 1
fi

# Count how many ARG_RANGE arguments we successfully validated, for
# the pass line.
total_range=$(grep -h "ARG_RANGE" "$ROOT"/syscalls/*.c 2>/dev/null \
	| grep -oE 'ARG_RANGE' | wc -l)
echo "PASS: $NAME (ARG_RANGE occurrences validated: $total_range)"
exit 0
