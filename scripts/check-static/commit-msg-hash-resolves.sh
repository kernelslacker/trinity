#!/bin/bash
#
# commit-msg-hash-resolves.sh -- verify that every hex-hash citation in
# recent commit messages both exists as a git object AND is reachable
# from HEAD.
#
# Background: the cherry-pick flow used during upstream integration
# rewrites commit hashes.  A commit message that says "see abc123..."
# may cite a hash that (a) does not exist at all (old history, harmless
# but stale), (b) exists as a dangling object but was never merged into
# master, or (c) exists and is reachable.  Class (b) is the dangerous
# one: `git cat-file -t <hash>` returns "commit" so it looks valid,
# but the commit it describes is from a now-orphaned cherry-pick branch
# and points at the wrong context.  A reader who follows the hash finds
# a commit that may share a subject with the intended one but has
# different parents, different metadata, and may differ in detail.
#
# The correct two-part check is:
#   1. git cat-file -t <hash>         -- object exists
#   2. git merge-base --is-ancestor <hash> HEAD  -- reachable from HEAD
# Only passing both is safe.  Failing (1) is merely stale; failing (2)
# while passing (1) is the dangerous class caught here.
#
# Scope: commit messages in a log range, not all of history.  Old
# commits routinely cite Linux kernel hashes that have no presence in
# this repo at all; those fall in the not-an-object category and are
# deliberately skipped.  The gate is meant to catch NEW citations that
# miss the correct reachable hash, not to retroactively flag the entire
# immutable history.
#
# Usage:
#   commit-msg-hash-resolves.sh [<git-log-range>]
#
# If no range is given, defaults to the last 200 commits on HEAD.
# The range is passed directly to `git log`, so any form accepted by
# git log works: "HEAD~200..HEAD", "v1.0..HEAD", "<since-sha>..HEAD".
#
# Follow the house check-static conventions:
#   PASS: <name> (<n> hashes checked, 0 unreachable)
#   FAIL: <name>: <n> unreachable hash citation(s)  (exit 1)
#

set -u

NAME="commit-msg-hash-resolves"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# Accept either a single git-log range or two <since> <until> args.
if [ $# -ge 2 ]; then
	RANGE="${1}..${2}"
elif [ $# -eq 1 ]; then
	RANGE="$1"
else
	RANGE="HEAD~200..HEAD"
fi

fail() {
	echo "FAIL: $NAME: $*"
	exit 1
}

pass() {
	echo "PASS: $NAME: $*"
	exit 0
}

# Extract all hex tokens (12-40 chars, no leading-zero-only purely-decimal
# sequences) from commit message bodies (subject + body, not the SHA column).
# We use --format=%B to get the raw message body without the commit hash.
# Pure-decimal tokens (e.g. large numbers used in comments) are skipped;
# a valid git hash must have at least one a-f character.
hex_tokens=$(
	git log --format="%B" "$RANGE" 2>/dev/null \
	| grep -oE '\b[0-9a-f]{12,40}\b' \
	| grep -vE '^[0-9]+$' \
	| sort -u
)

if [ -z "$hex_tokens" ]; then
	pass "range $RANGE: 0 hashes in commit messages, nothing to check"
fi

checked=0
skipped=0
unreachable=0
unreachable_detail=""

while IFS= read -r tok; do
	[ -n "$tok" ] || continue

	# Count every token evaluated, regardless of what follows.
	checked=$((checked + 1))

	# Step 1: does the object exist at all?
	if ! git cat-file -t "$tok" >/dev/null 2>&1; then
		# Not an object in this repo (stale external reference,
		# Linux kernel hash, or pruned by GC).  Count as skipped.
		skipped=$((skipped + 1))
		continue
	fi

	# Step 2: is it reachable from HEAD?
	if ! git merge-base --is-ancestor "$tok" HEAD 2>/dev/null; then
		unreachable=$((unreachable + 1))
		# Find which commit message(s) contain this citation
		citing=$(git log --format="%h %s" "$RANGE" --grep="$tok" 2>/dev/null \
			| head -3 | sed 's/^/    /')
		subject=$(git log --format="%s" "$tok" 2>/dev/null | head -1)
		unreachable_detail=$(printf '%s\n  %s (%s)\n%s' \
			"$unreachable_detail" "$tok" "$subject" "$citing")
	fi
done <<< "$hex_tokens"

if [ "$unreachable" -gt 0 ]; then
	{
		echo "  $NAME: $unreachable unreachable hash citation(s) in commit messages"
		echo "  range: $RANGE"
		echo "  These hashes exist as git objects but are NOT reachable from HEAD."
		echo "  They are dangling objects from cherry-pick rewriting, not the"
		echo "  correct master commits.  Find the right hash by subject-matching:"
		echo "    git log --oneline | grep -i '<subject keywords>'"
		echo "  then update the citing commit message to use the reachable hash."
		echo ""
		echo "  Unreachable citations:$unreachable_detail"
	} >&2
	fail "$unreachable unreachable hash citation(s) in range $RANGE ($checked object-hashes checked)"
fi

pass "range $RANGE: $checked hashes checked, $skipped skipped-not-object, 0 unreachable"
