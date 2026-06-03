#!/bin/bash
#
# srec-no-lock-around-publish: the srec publish brackets are a
# self-sufficient writer-side ordering anchor (see syscall_record.h);
# pairing them with a rec->lock acquire/release reintroduces the very
# lock the strengthening commit set out to remove and signals a habit
# regression rather than an intentional design choice.
#
# Flag any of these adjacent patterns (separated by at most a blank
# line and/or a single comment line):
#   lock(&...->lock);
#   srec_publish_begin(...);
#
#   srec_publish_end(...);
#   unlock(&...->lock);
#
# The check is line-anchored on the brackets, so a lock(&X) that is
# not next to a publish call (e.g. shm->syscalltable_lock around
# deactivate_syscall_nolock) is correctly ignored.

set -u

NAME="srec-no-lock-around-publish"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# Walk every C source file once.  For each line buffer the previous
# three non-blank, non-comment lines so we can spot the adjacency
# regardless of intervening whitespace or a brief comment.
scan() {
	awk '
		function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
		function meaningful(s,    t) {
			t = trim(s)
			if (t == "") return 0
			if (t ~ /^\/\//) return 0
			if (t ~ /^\/\*/) return 0
			if (t ~ /^\*/) return 0
			return 1
		}
		{
			line = $0
			if (!meaningful(line)) next
			t = trim(line)
			# pattern A: lock immediately before publish_begin
			if (prev ~ /^lock\([^)]*->lock\)[[:space:]]*;/ &&
			    t ~ /^srec_publish_begin[[:space:]]*\(/) {
				print FILENAME ":" prev_lineno ": lock(...->lock) immediately precedes srec_publish_begin"
			}
			# pattern B: unlock immediately after publish_end
			if (prev ~ /^srec_publish_end[[:space:]]*\(/ &&
			    t ~ /^unlock\([^)]*->lock\)[[:space:]]*;/) {
				print FILENAME ":" FNR ": unlock(...->lock) immediately follows srec_publish_end"
			}
			prev = t
			prev_lineno = FNR
		}
		BEGINFILE { prev = ""; prev_lineno = 0 }
	' "$@"
}

mapfile -t SRCFILES < <(find . \( -name '*.c' -o -name '*.h' \) -type f \
		-not -path './.git/*' -print | sort)

if [ "${#SRCFILES[@]}" -eq 0 ]; then
	echo "FAIL: $NAME: no source files found"
	exit 1
fi

scan "${SRCFILES[@]}" > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: rec->lock acquire/release adjacent to srec publish brackets:"
		while IFS= read -r hit; do
			echo "    $hit"
		done < "$hits_tmp"
		echo "  fix: drop the lock/unlock pair -- the publish brackets are"
		echo "       the writer-side ordering anchor (see syscall_record.h)."
	} >&2
	echo "FAIL: $NAME: $n adjacency violation(s)"
	exit 1
fi

echo "PASS: $NAME: 0 lock/unlock pairs adjacent to srec publish brackets"
exit 0
