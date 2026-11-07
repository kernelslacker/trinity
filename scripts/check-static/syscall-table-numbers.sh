#!/bin/bash
#
# syscall-table-numbers: every entry of a syscall table sits at its
# syscall's number.  do_syscall() issues the table index, so an entry a
# slot off runs a different syscall than the one its descriptor built the
# arguments for.  The numbers come from the build host's uapi
# <asm/unistd_*.h>: a table whose header the host cannot preprocess is
# skipped, as is an entry whose name the header does not define.  An
# entry may also sit at its name's 32-bit-uid or y2038 twin
# (__NR_<name>32, __NR_<name>64, __NR_<name>_time64).

set -u

NAME="syscall-table-numbers"
ROOT="${REPO_ROOT:-$(pwd)}"

command -v gcc >/dev/null 2>&1 || { echo "ERROR: $NAME: gcc unavailable"; exit 1; }

# <table header under include/>:<uapi header holding its numbers>
TABLES="syscalls-x86_64.h:asm/unistd_64.h"

problems=""
checked=0
for pair in $TABLES; do
	table="$ROOT/include/${pair%%:*}"
	nrs=$(echo "#include <${pair#*:}>" | gcc -dM -E - 2>/dev/null |
		awk '$1 == "#define" && $2 ~ /^__NR_/ && $3 ~ /^[0-9]+$/ {
			print substr($2, 6), $3
		}')
	[ -n "$nrs" ] || continue
	checked=$((checked + 1))
	# The #else arm of a config switch is the same slot's other value.
	found=$(printf '%s\n' "$nrs" | awk -v file="${table#"$ROOT"/}" '
		FNR == NR { nr[$1] = $2; next }
		/^#else/ { skip = 1; next }
		/^#endif/ { skip = 0; next }
		skip { next }
		match($0, /\.entry = (&syscall_[A-Za-z0-9_]+|NULL)/) {
			idx = n++
			name = substr($0, RSTART + 9, RLENGTH - 9)
			if (name == "NULL")
				next
			sub(/^&syscall_/, "", name)
			if (name == "ni_syscall")
				next
			split(name " " name "32 " name "64 " name "_time64", cand, " ")
			at = ""
			for (c in cand) {
				if (!(cand[c] in nr))
					continue
				if (nr[cand[c]] == idx)
					next
				at = at " __NR_" cand[c] "=" nr[cand[c]]
			}
			if (at != "")
				printf "%s: slot %d holds syscall_%s, but%s\n", file, idx, name, at
		}
	' - "$table")
	[ -n "$found" ] && problems="$problems$found"$'\n'
done

if [ "$checked" -eq 0 ]; then
	echo "WARN: $NAME: no table's uapi header on this host"
	exit 0
fi

if [ -n "$problems" ]; then
	echo "FAIL: $NAME: syscall table entries off their syscall numbers"
	printf '%s' "$problems" | sed 's/^/  /' >&2
	exit 1
fi

echo "PASS: $NAME (tables checked: $checked)"
exit 0
