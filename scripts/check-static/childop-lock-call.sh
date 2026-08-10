#!/bin/bash
#
# childop-lock-call: flag any lock(), bust_lock(), or force_bust_lock() call
# sites anywhere in the whole tree.
#
# cached_pid is COW-inherited across fork() and is never refreshed, so it is
# not process-unique in a grandchild (see utils/locks.c bust_lock() note).
# A grandchild that called lock() would encode the parent's pid as the lock
# owner, misfire or skip the self-deadlock guard, and block force_bust_lock()
# from recovering an orphan held by a dead grandchild.  bust_lock() and
# force_bust_lock() carry the same cached_pid hazard (they read/write
# LOCK_OWNER) and are covered by this gate for the same reason.
#
# All 14 known lock() call sites are on the child_process() dispatch path
# (audited in 96e7cd26ef56 ("locks: document cached_pid COW-fork caveat at bust_lock()")
# and 60b11ae678b5 ("check-static: flag childop lock() calls for grandchild review")).
# utils/locks.c (implementation) and main/reap.c (force_bust_lock recovery)
# are excluded by name.
# No other code in the whole tree reaches lock(), bust_lock(), or
# force_bust_lock().  This check ensures that invariant is not silently broken
# by a future patch.
#
# Pattern: lock(), bust_lock(), force_bust_lock() -- all cached_pid consumers.

set -u

NAME="childop-lock-call"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

warn_count=0

while IFS= read -r srcfile; do
	# Skip known-audited dispatch-path sites and the lock implementation itself.
	case "${srcfile#./}" in
		cmp_hints/field.c|\
		cmp_hints/pool.c|\
		random_syscall/chain-persist.c|\
		random_syscall/chain-corpus.c|\
		args/pools/blob_corpus.c|\
		tables/table-activate.c|\
		persist/minicorpus-core.c|\
		dispatch/syscall-exec.c|\
		dispatch/syscall-post.c|\
		child/child-periodic.c|\
		utils/locks.c|\
		main/reap.c)
			continue ;;
	esac

	while IFS= read -r match; do
		lineno="${match%%:*}"
		content="${match#*:}"
		trimmed="${content#"${content%%[![:space:]]*}"}"

		# Skip comment lines (block-comment continuation, opening /* or //).
		case "$trimmed" in
			\**)  continue ;;
			/\**) continue ;;
			//*)  continue ;;
		esac

		echo "WARN: ${srcfile#./}:${lineno}: lock/bust_lock/force_bust_lock called -- verify grandchild-unreachability (see utils/locks.c bust_lock() note)"
		warn_count=$((warn_count + 1))
	done < <(grep -En '\b(lock|bust_lock|force_bust_lock)\s*\(' "$srcfile" 2>/dev/null)
done < <(find . -name '*.c' -type f | sort)

if [ "$warn_count" -gt 0 ]; then
	{
		echo "  $NAME: $warn_count lock/bust_lock/force_bust_lock call(s) found in the whole tree"
		echo "  cached_pid is COW-inherited and not process-unique in grandchildren."
		echo "  Confirm the call site is unreachable from any fork()'d grandchild,"
		echo "  then update the audit note in utils/locks.c bust_lock()."
	} >&2
	exit 1
fi

echo "PASS: $NAME: no new lock/bust_lock/force_bust_lock calls in the whole tree"
exit 0
