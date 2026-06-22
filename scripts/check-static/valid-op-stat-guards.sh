#!/bin/bash
#
# valid-op-stat-guards: flag two adjacent `if (valid_op)` guards on
# the childop accounting writes that should collapse into one.
#
# The childop accounting pair
#
#     if (valid_op)
#             __atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
#                                1, __ATOMIC_RELAXED);
#
#     if (valid_op)
#             __atomic_add_fetch(&shm->stats.childop_data_path[op],
#                                1, __ATOMIC_RELAXED);
#
# is the canonical accept-then-progress trace for a childop and the
# two stores belong under the SAME guard:
#
#     if (valid_op) {
#             __atomic_add_fetch(&shm->stats.childop_setup_accepted[op],
#                                1, __ATOMIC_RELAXED);
#             __atomic_add_fetch(&shm->stats.childop_data_path[op],
#                                1, __ATOMIC_RELAXED);
#     }
#
# Two separate guards re-evaluate the same bounds-check, drop a
# compiler optimisation barrier into the middle of two accounting-only
# stores, and (more importantly) skew the two counters apart if the
# guard expression ever grows side-effects.  The tree was collapsed
# clean; this check exists to keep it that way.
#
# What is flagged:
#   * a bare or braced `if (valid_op)` whose body writes
#     `childop_setup_accepted[`, immediately followed (blank lines only
#     in between) by another `if (valid_op)` whose body writes
#     `childop_data_path[`.
#
# What is NOT flagged:
#   * a single combined `if (valid_op) { setup_accepted; data_path; }`
#   * two guards separated by any non-blank statement
#   * either store standing alone
#   * any other `if (valid_op)` usage

set -u

NAME="valid-op-stat-guards"
ROOT="${REPO_ROOT:-$(pwd)}"

if [ ! -d "$ROOT/childops" ]; then
	echo "PASS: $NAME (no childops/ directory)"
	exit 0
fi

tmp_out=$(mktemp)
trap 'rm -f "$tmp_out"' EXIT

while IFS= read -r srcfile; do
	awk -v file="${srcfile#"$ROOT"/}" '
		{ lines[NR] = $0 }

		END {
			n = NR
			for (i = 1; i <= n; i++) {
				end1 = guard_end(i, "childop_setup_accepted[", n)
				if (end1 == 0)
					continue
				j = end1 + 1
				while (j <= n && lines[j] ~ /^[[:space:]]*$/)
					j++
				if (j > n)
					continue
				end2 = guard_end(j, "childop_data_path[", n)
				if (end2 == 0)
					continue
				printf "%s:%d: setup_accepted guard at line %d adjacent to data_path guard at line %d -- collapse under one if (valid_op)\n",
					file, i, i, j
			}
		}

		function guard_end(start, marker, total,    line, idx, body, depth, l, k, c) {
			line = lines[start]
			if (line ~ /^[[:space:]]*if[[:space:]]*\([[:space:]]*valid_op[[:space:]]*\)[[:space:]]*$/) {
				body = ""
				idx = start + 1
				while (idx <= total) {
					body = body "\n" lines[idx]
					if (lines[idx] ~ /;[[:space:]]*(\/\/.*)?$/) {
						if (index(body, marker) > 0)
							return idx
						return 0
					}
					idx++
				}
				return 0
			}
			if (line ~ /^[[:space:]]*if[[:space:]]*\([[:space:]]*valid_op[[:space:]]*\)[[:space:]]*\{/) {
				body = ""
				depth = 0
				idx = start
				while (idx <= total) {
					body = body "\n" lines[idx]
					l = lines[idx]
					gsub(/[^{}]/, "", l)
					for (k = 1; k <= length(l); k++) {
						c = substr(l, k, 1)
						if (c == "{")
							depth++
						else
							depth--
						if (depth == 0) {
							if (index(body, marker) > 0)
								return idx
							return 0
						}
					}
					idx++
				}
				return 0
			}
			return 0
		}
	' "$srcfile" >> "$tmp_out"
done < <(find "$ROOT/childops" -maxdepth 1 -name "*.c" | sort)

if [ -s "$tmp_out" ]; then
	hits=$(wc -l < "$tmp_out")
	echo "FAIL: $NAME: $hits adjacent if (valid_op) stat guard pair(s)"
	while IFS= read -r line; do
		echo "  $line" >&2
	done < "$tmp_out"
	echo "  collapse into: if (valid_op) { setup_accepted += 1; data_path += 1; }" >&2
	exit 1
fi

echo "PASS: $NAME (no adjacent valid_op stat guards found)"
exit 0
