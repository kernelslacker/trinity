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
# If no range is given, defaults to origin/master..HEAD (the commits not
# yet pushed); if there is no such range the gate passes (it never scans
# history-wide).  The range is passed directly to `git log`, so any form
# accepted by git log works: "HEAD~200..HEAD", "v1.0..HEAD",
# "<since-sha>..HEAD".
#
# Follow the house check-static conventions:
#   PASS: <name> (<n> hashes checked, 0 unreachable)
#   FAIL: <name>: <n> unreachable hash citation(s)  (exit 1)
#

set -u

NAME="commit-msg-hash-resolves"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# Grandfathered dangling citations (pre-existing cherry-pick orphans).
# Path overridable for testing via HASH_RESOLVE_BASELINE.
BASELINE="${HASH_RESOLVE_BASELINE:-$ROOT/scripts/check-static/commit-msg-hash-resolves.baseline}"
GRANDFATHERED=""
if [ -f "$BASELINE" ]; then
	GRANDFATHERED=$(grep -vE '^[[:space:]]*(#|$)' "$BASELINE" 2>/dev/null)
fi
grandfathered=0

# Accept either a single git-log range or two <since> <until> args.
# With no argument the gate defaults to origin/master..HEAD so it checks
# only the commits not yet pushed to origin — the natural scope for a
# precommit gate.  When origin/master is unavailable or equal to HEAD
# (nothing unpushed) the gate passes: there is no new range to check and
# it must never litigate history-wide (that caused a prior suite block).
if [ $# -ge 2 ]; then
	RANGE="${1}..${2}"
elif [ $# -eq 1 ]; then
	RANGE="$1"
elif git rev-parse --verify origin/master >/dev/null 2>&1 \
	&& [ "$(git rev-parse origin/master)" != "$(git rev-parse HEAD)" ]; then
	RANGE="origin/master..HEAD"
else
	# No origin/master, or nothing unpushed (origin/master == HEAD).
	# Do NOT fall back to a history-wide HEAD~200..HEAD window: that
	# re-litigates immutable, already-pushed history and was the cause
	# of a prior suite-wide block.  The gate's job is to catch NEW
	# unreachable citations in unpushed work; with no such range there
	# is nothing to check.
	echo "PASS: $NAME: no unpushed range (origin/master unavailable or == HEAD); nothing to check"
	exit 0
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
#
# upstream: prefix escape: tokens immediately preceded by "upstream:" (with or
# without a space after the colon) are external references and must not be
# checked against this repo.  Elide them before extraction so they are never
# seen by the loop.  Both forms from the doc convention are covered:
#   upstream:abc123def456        (no space)
#   upstream: abc123def456       (space after colon)
hex_tokens=$(
	git log --format="%B" "$RANGE" 2>/dev/null \
	| sed -E 's/upstream:[[:space:]]*([0-9a-f]{12,40})/UPSTREAM_ELIDED/g' \
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
wrong_citation=0
wrong_citation_detail=""

while IFS= read -r tok; do
	[ -n "$tok" ] || continue

	# Count every token evaluated, regardless of what follows.
	checked=$((checked + 1))

	# Step 1: does the object exist at all?
	if ! git cat-file -t "$tok" >/dev/null 2>&1; then
		# Not an object in this repo.  Before treating as merely skipped,
		# attempt to resolve the citation by its adjacent subject annotation.
		# If the citing commit carries the hash-subject convention form
		#   <hash> ("<subject>")  or  <hash> ('<subject>')
		# and a reachable commit with that exact subject exists, the citation
		# is provably wrong (we know the right hash) — FAIL.
		#
		# Subject extraction: find lines in the citing commit body that
		# contain the token followed by ("...") or ('...').
		adjacent_subj=""
		citing_body=$(
			git log --format="%B" "$RANGE" --grep="$tok" 2>/dev/null
		)
		if [ -n "$citing_body" ]; then
			# Subjects may wrap across lines (e.g. a long subject that the
			# author folded at the terminal width).  Join all lines with a
			# space first, then look for: <tok>[spaces](<subject>)
			# The <subject> is between the parentheses, with optional
			# leading/trailing quote chars stripped.
			adjacent_subj=$(
				printf '%s\n' "$citing_body" | tr '\n' ' ' | \
				grep -oE "${tok}[[:space:]]+\([^)]+\)" | \
				sed "s/${tok}[[:space:]]*(//;s/)\$//" | \
				tr -d "\"'" | head -1
			)
		fi

		# Fallback: if no adjacent subject found in-line, run the
		# hash-subject-resolver against the token; for NOT-AN-OBJECT
		# tokens the resolver searches the log for the literal token
		# string, which may surface a citing commit whose body contains
		# an annotated twin line we can then re-parse.
		if [ -z "$adjacent_subj" ]; then
			_rtmp=$(mktemp /tmp/hash-gate-resolver-XXXXXX)
			printf '%s\n' "$tok" > "$_rtmp"
			_rout=$(
				"$ROOT/scripts/hash-subject-resolver.sh" "$_rtmp" 2>/dev/null
			) || true
			rm -f "$_rtmp"
			# Resolver returns NOT-AN-OBJECT-WITH-TWIN when it finds a
			# commit whose body contains the token.  Extract that
			# commit's body and attempt subject parsing from it.
			_rciting=$(
				printf '%s\n' "$_rout" | \
				grep 'NOT-AN-OBJECT-WITH-TWIN' | \
				awk '{print $3}' | head -1
			)
			if [ -n "$_rciting" ]; then
				_rbody=$(
					git log -1 --format="%B" "$_rciting" 2>/dev/null
				)
				adjacent_subj=$(
					printf '%s\n' "$_rbody" | grep -F "$tok" | \
					sed -n "s/.*${tok}[[:space:]]*(\([^)]*\)).*/\1/p" | \
					tr -d "\"'" | head -1
				)
			fi
		fi

		if [ -n "$adjacent_subj" ]; then
			# Search all of HEAD for a reachable commit whose SUBJECT
			# (not body) exactly matches the adjacent annotation.
			# Using --grep would match any commit whose full message body
			# contains the subject string (e.g. another commit that CITES
			# the same token), producing false positives.  Instead, scan
			# "%H %s" output and compare the subject field exactly.
			twin_hash=$(
				git log --format="%H %s" 2>/dev/null | \
				awk -v subj="$adjacent_subj" '{
					h = $1; sub(/^[^ ]+ /, "")
					if ($0 == subj) { print substr(h,1,12); exit }
				}'
			)
			if [ -n "$twin_hash" ]; then
				wrong_citation=$((wrong_citation + 1))
				citing_loc=$(
					git log --format="%h %s" "$RANGE" \
						--grep="$tok" 2>/dev/null | \
					head -3 | sed 's/^/    /'
				)
				wrong_citation_detail=$(
					printf '%s\n  %s (subject: "%s")\n  → right hash: %s\n%s' \
						"$wrong_citation_detail" \
						"$tok" \
						"$adjacent_subj" \
						"$twin_hash" \
						"$citing_loc"
				)
				continue
			fi
		fi

		# No adjacent subject found, or subject found but no reachable
		# twin: genuinely unresolvable (old history, external hash before
		# the upstream: convention, or GC-pruned with no subject match).
		skipped=$((skipped + 1))
		continue
	fi

	# Step 2: is it reachable from HEAD?
	if ! git merge-base --is-ancestor "$tok" HEAD 2>/dev/null; then
		if [ -n "$GRANDFATHERED" ] && \
		   printf '%s\n' "$GRANDFATHERED" | grep -qxF "$tok"; then
			grandfathered=$((grandfathered + 1))
			continue
		fi
		unreachable=$((unreachable + 1))
		# Find which commit message(s) contain this citation
		citing=$(git log --format="%h %s" "$RANGE" --grep="$tok" 2>/dev/null \
			| head -3 | sed 's/^/    /')
		subject=$(git log --format="%s" "$tok" 2>/dev/null | head -1)
		unreachable_detail=$(printf '%s\n  %s (%s)\n%s' \
			"$unreachable_detail" "$tok" "$subject" "$citing")
	fi
done <<< "$hex_tokens"

if [ "$unreachable" -gt 0 ] || [ "$wrong_citation" -gt 0 ]; then
	{
		if [ "$unreachable" -gt 0 ]; then
			echo "  $NAME: $unreachable unreachable hash citation(s) in commit messages"
			echo "  range: $RANGE"
			echo "  These hashes exist as git objects but are NOT reachable from HEAD."
			echo "  They are dangling objects from cherry-pick rewriting, not the"
			echo "  correct master commits.  Find the right hash by subject-matching:"
			echo "    git log --oneline | grep -i '<subject keywords>'"
			echo "  then update the citing commit message to use the reachable hash."
			echo ""
			echo "  Unreachable citations:$unreachable_detail"
		fi
		if [ "$wrong_citation" -gt 0 ]; then
			echo ""
			echo "  $NAME: $wrong_citation not-an-object citation(s) with a provably-wrong hash"
			echo "  range: $RANGE"
			echo "  These tokens are not git objects in this repo but their adjacent"
			echo "  subject annotation matches a reachable commit under a different hash."
			echo "  The cherry-pick flow rewrote the SHA; update the citation to the"
			echo "  right hash shown below (the subject survived, the hash did not)."
			echo ""
			echo "  Wrong citations:$wrong_citation_detail"
		fi
	} >&2
	total_errors=$((unreachable + wrong_citation))
	fail "$total_errors citation error(s) in range $RANGE ($checked hashes checked)"
fi

pass "range $RANGE: $checked checked, $skipped skipped, $grandfathered grandfathered, 0 unreachable"
