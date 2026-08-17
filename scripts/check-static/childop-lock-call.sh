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
# (audited in a7170a389132 ("locks: document cached_pid COW-fork caveat at bust_lock()")
# and 0a98a973d953 ("check-static: flag childop lock() calls for grandchild review")).
# utils/locks.c (implementation) and main/reap.c (force_bust_lock recovery)
# are excluded by name.  All other audited sites are listed in
# childop-lock-call.allowlist by file:line:hash so that a new lock() call
# added to a previously-audited file is not silently passed, and so that
# updating a line number without re-auditing fails on hash mismatch.
# No other code in the whole tree reaches lock(), bust_lock(), or
# force_bust_lock().  This check ensures that invariant is not silently broken
# by a future patch.
#
# Pattern: lock(), bust_lock(), force_bust_lock() -- all cached_pid consumers.

set -u

NAME="childop-lock-call"
ROOT="${REPO_ROOT:-$(pwd)}"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

declare -A allowlist
declare -A allowlist_matched
while IFS= read -r entry; do
	[[ -z "$entry" || "$entry" == \#* ]] && continue
	_key="${entry%%[[:space:]]*}"
	allowlist["$_key"]=1
done < "$SCRIPT_DIR/childop-lock-call.allowlist"

warn_count=0

while IFS= read -r srcfile; do
	# Skip the lock implementation and the force_bust_lock recovery loop.
	case "${srcfile#./}" in
		utils/locks.c|\
		main/reap.c)
			continue ;;
	esac

	while IFS= read -r match; do
		lineno="${match%%:*}"
		content="${match#*:}"
		trimmed=$(printf '%s' "$content" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

		# Skip comment lines (block-comment continuation, opening /* or //).
		case "$trimmed" in
			\**)  continue ;;
			/\**) continue ;;
			//*)  continue ;;
		esac

		# Skip known-audited call sites listed in the allowlist.
		# Key format is file:line:hash where hash is the first 8 hex chars
		# of sha256 of the both-ends-trimmed line content.  Both the line
		# number and the content must match; updating a line number without
		# re-auditing will fail on hash mismatch.
		# Limitation: two sites with identical source text hash to the same
		# value, so a bulk-renumber pointing an entry at a different
		# same-text line in the same file passes both checks.
		hash=$(printf '%s' "$trimmed" | sha256sum | cut -c1-8)
		key="${srcfile#./}:$lineno:$hash"
		if [ "${allowlist[$key]+set}" ]; then allowlist_matched[$key]=1; continue; fi

		echo "WARN: $key: lock/bust_lock/force_bust_lock called -- verify grandchild-unreachability (see utils/locks.c bust_lock() note)"
		warn_count=$((warn_count + 1))
	done < <(grep -En '\b(lock|bust_lock|force_bust_lock)\s*\(' "$srcfile" 2>/dev/null)
done < <(find . -name '*.c' -type f | sort)

# Dead-allowlist check: every key loaded from the allowlist must have matched
# at least one grep hit.  A key that never matched means the site drifted
# (source edited above the site) or was removed; the entry is now a dead
# suppression and could silently pass a new unaudited site at the same line.
dead_count=0
for _k in "${!allowlist[@]}"; do
	if [ -z "${allowlist_matched[$_k]+x}" ]; then
		echo "DEAD ALLOWLIST ENTRY: $_k" >&2
		dead_count=$((dead_count + 1))
	fi
done
if [ "$dead_count" -gt 0 ]; then
	{
		echo "  $NAME: $dead_count dead allowlist entry/entries (never matched by scanner)"
		echo "  The file:line:hash key did not match: line number changed, site text changed,"
		echo "  or the site was removed.  Re-derive the correct key or remove the stale entry from:"
		echo "    scripts/check-static/childop-lock-call.allowlist"
	} >&2
	echo "FAIL: $NAME: $dead_count dead allowlist entry/entries"
	exit 1
fi

if [ "$warn_count" -gt 0 ]; then
	{
		echo "  $NAME: $warn_count lock/bust_lock/force_bust_lock call(s) found in the whole tree"
		echo "  cached_pid is COW-inherited and not process-unique in grandchildren."
		echo "  Confirm the call site is unreachable from any fork()'d grandchild,"
		echo "  then update the audit note in utils/locks.c bust_lock() and"
		echo "  add the new site to scripts/check-static/childop-lock-call.allowlist."
	} >&2
	exit 1
fi

echo "PASS: $NAME: no new lock/bust_lock/force_bust_lock calls in the whole tree"
exit 0
