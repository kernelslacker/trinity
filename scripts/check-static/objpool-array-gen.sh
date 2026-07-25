#!/bin/bash
#
# objpool-array-gen: enforce the array_generation invariant on
# struct objhead.  An indexed read off head->array is only safe when
# the array container has not been freed and replaced between the
# reader's snapshot and its arr[idx] load -- the deferred-free TTL on
# OBJ_LOCAL grow and the plain free() on OBJ_GLOBAL grow / pool
# teardown all turn the captured pointer into a chunk glibc may have
# already handed back to a fresh malloc.  The gate that catches that
# is array_generation: every write to head->array is followed by an
# array_generation++, and the indexed-read helper re-reads
# array_generation after its load and discards the pick on mismatch.
#
# Three structural invariants this check enforces:
#
#   1. struct objhead carries an array_generation field.
#   2. get_random_object() routes its indexed read through the
#      objhead_indexed_read() helper (no bare head->array[idx] load).
#   3. Every site that frees or replaces head->array is followed --
#      within a small window of source lines -- by a head->array_
#      generation++ bump.  The three known sites are the two
#      add_object_grow_capacity branches and destroy_objects().
#
# These are checked as line-anchored greps so the script stays cheap
# and stable under unrelated refactoring of objects.c.

set -u

NAME="objpool-array-gen"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

OBJ_H="include/objects.h"
# Registry logic is split across objects/registry*.c sibling TUs
# (registry.c + registry-lifecycle.c + registry-pool.c + registry-pick.c
# + registry-diag.c).  The checks below scan all of them.
OBJ_C_LIST="objects/registry.c objects/registry-lifecycle.c objects/registry-pool.c objects/registry-pick.c objects/registry-diag.c"

fail=0

# (1) field exists on struct objhead.
if ! grep -qE '^[[:space:]]+unsigned int array_generation;' "$OBJ_H"; then
	echo "FAIL: $NAME: struct objhead missing array_generation field in $OBJ_H"
	fail=1
fi

# (2) get_random_object() must not contain a bare head->array[ ... ]
# indexed load (the pre-fix form).  It MUST contain a call to
# objhead_indexed_read instead.  Extract the function body by brace
# tracking and inspect it -- search across the registry-*.c set for
# the TU that defines it.
body=""
body_file=""
for f in $OBJ_C_LIST; do
	[ -f "$f" ] || continue
	b="$(awk '
		/^struct object \* get_random_object\(/ { in_fn=1; depth=0 }
		in_fn {
			print
			n_open=gsub(/\{/, "{")
			n_close=gsub(/\}/, "}")
			depth += n_open - n_close
			if (depth > 0) seen=1
			if (seen && depth == 0) { exit }
		}
	' "$f")"
	if [ -n "$b" ]; then
		body="$b"
		body_file="$f"
		break
	fi
done

if [ -z "$body" ]; then
	echo "FAIL: $NAME: could not locate get_random_object() body in $OBJ_C_LIST"
	fail=1
else
	if echo "$body" | grep -qE 'head->array\['; then
		echo "FAIL: $NAME: get_random_object() still contains a bare head->array[idx] indexed load (in $body_file)"
		echo "$body" | grep -nE 'head->array\[' >&2
		fail=1
	fi
	if ! echo "$body" | grep -qE 'objhead_indexed_read\('; then
		echo "FAIL: $NAME: get_random_object() does not route through objhead_indexed_read() (in $body_file)"
		fail=1
	fi
fi

# (3) every array-replace site must be paired with an array_generation++
# within a small window of source lines (before or after — the OBJ_LOCAL
# grow bumps before the deferred-free hand-off so the captured stamp is
# already invalidated by the time the old container enters the TTL ring;
# the OBJ_GLOBAL grow and the destroy_objects() teardown bump after the
# free/replace.  All three patterns are accepted).
#
# Three known anchor shapes:
#   free(head->array);              -- OBJ_GLOBAL grow
#   deferred_free_enqueue(oldarray);-- OBJ_LOCAL grow
#   tracked_free_now(head->array);  -- destroy_objects teardown
#
# Walk each registry-*.c file collecting (anchor_line, label) and
# (bump_lines).  Each anchor must have a bump within +/- 12 lines
# of the SAME file (anchors and bumps are always co-located in the
# same TU because the array-replace + generation-bump lines are one
# atomic sequence in the source).

total_anchors=0
for f in $OBJ_C_LIST; do
	[ -f "$f" ] || continue
	awk -v NAME="$NAME" '
		BEGIN { exit_code = 0; nb = 0; na = 0 }
		$0 ~ /head->array_generation\+\+;/ { bumps[nb++] = NR }
		$0 ~ /free\(head->array\);/        { anchors[na] = NR; labels[na] = "free(head->array)"; na++ }
		$0 ~ /tracked_free_now\(head->array\);/ { anchors[na] = NR; labels[na] = "tracked_free_now(head->array)"; na++ }
		$0 ~ /deferred_free_enqueue\(oldarray\);/ { anchors[na] = NR; labels[na] = "deferred_free_enqueue(oldarray)"; na++ }
		END {
			for (i = 0; i < na; i++) {
				found = 0
				for (j = 0; j < nb; j++) {
					if (bumps[j] >= anchors[i] - 12 && bumps[j] <= anchors[i] + 12) {
						found = 1
						break
					}
				}
				if (!found) {
					printf("FAIL: %s: replace site %s at %s:%d not paired with head->array_generation++ within +/-12 lines\n",
						NAME, labels[i], FILENAME, anchors[i]) > "/dev/stderr"
					exit_code = 1
				}
			}
			printf("%d\n", na)
			exit exit_code
		}
	' "$f" > /tmp/objpool-check-$$-count 2>/tmp/objpool-check-$$-err
	awk_rc=$?
	na_here=$(cat /tmp/objpool-check-$$-count 2>/dev/null)
	cat /tmp/objpool-check-$$-err >&2 2>/dev/null
	rm -f /tmp/objpool-check-$$-count /tmp/objpool-check-$$-err
	if [ "$awk_rc" -ne 0 ]; then
		fail=1
	fi
	if [ -n "$na_here" ]; then
		total_anchors=$((total_anchors + na_here))
	fi
done

if [ "$total_anchors" -eq 0 ]; then
	echo "FAIL: $NAME: no array-replace anchor sites found in $OBJ_C_LIST -- check script may be stale" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	echo "FAIL: $NAME"
	exit 1
fi

echo "PASS: $NAME"
exit 0
