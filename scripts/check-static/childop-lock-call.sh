#!/bin/bash
#
# childop-lock-call: flag any lock() call sites that appear inside childops/.
#
# cached_pid is COW-inherited across fork() and is never refreshed, so it is
# not process-unique in a grandchild (see utils/locks.c bust_lock() note).
# A grandchild that called lock() would encode the parent's pid as the lock
# owner, misfire or skip the self-deadlock guard, and block force_bust_lock()
# from recovering an orphan held by a dead grandchild.
#
# All 14 lock(&...) call sites are on the child_process() dispatch path
# (audited in 96e7cd26ef56 ("locks: document cached_pid COW-fork caveat at bust_lock()")).
# No childop worker body or signal handler
# reaches lock().  This check ensures that invariant is not silently broken
# by a future patch.
#
# Pattern: "lock(&" -- the call form used at all known lock() sites.

set -u

NAME="childop-lock-call"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

if [ ! -d childops ]; then
	echo "PASS: $NAME: no childops/ directory"
	exit 0
fi

warn_count=0

while IFS= read -r srcfile; do
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

		echo "WARN: ${srcfile#./}:${lineno}: lock() called from childops -- verify grandchild-unreachability (see utils/locks.c bust_lock() note)"
		warn_count=$((warn_count + 1))
	done < <(grep -En '\block\(&' "$srcfile" 2>/dev/null)
done < <(find childops/ -name '*.c' -type f | sort)

if [ "$warn_count" -gt 0 ]; then
	{
		echo "  $NAME: $warn_count lock() call(s) found in childops/"
		echo "  cached_pid is COW-inherited and not process-unique in grandchildren."
		echo "  Confirm the call site is unreachable from any fork()\'d grandchild,"
		echo "  then update the audit note in utils/locks.c bust_lock()."
	} >&2
	exit 1
fi

echo "PASS: $NAME: no lock() calls in childops/"
exit 0
