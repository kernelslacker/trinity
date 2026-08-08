#!/bin/bash
#
# hash-subject-resolver.sh -- resolve stale hash citations to reachable twins.
#
# Usage: hash-subject-resolver.sh <file> [<file>...]
#
# For each 12–40 character lowercase hex token found in the given files,
# attempts to resolve it to a reachable commit in this repo.  The cherry-pick
# workflow rewrites every SHA, so any hash a committer embeds in a message or
# queue document stales the moment its ancestors are amended.  This tool finds
# the surviving twin by matching commit subjects.
#
# Output categories (one line per unique token per file):
#
#   FOUND                    hash is reachable from HEAD; subject printed
#   NOT-AN-OBJECT-WITH-TWIN  hash is not in the object store; a reachable
#                            commit with a matching subject was found via grep
#   DANGLING                 hash is in the object store but unreachable from
#                            HEAD; a reachable twin with the same subject found
#   DANGLING-NO-TWIN         dangling object; no reachable twin found
#   NOT-AN-OBJECT-NO-TWIN    hash is not in the object store; no twin found
#
# The script prints a rewrite map to stdout and exits 0 in all cases.
# It is an informational / repair-prep tool, not a build gate.
#
# Convention: every hash cited in a commit message, queue row, or review
# document should be accompanied by its commit subject in the form:
#   abc123def456 ("check-static: add …")
# The subject survives cherry-pick rewriting; the bare hash does not.

set -u

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

usage() {
	echo "Usage: $0 <file> [<file>...]" >&2
	exit 1
}

[ "$#" -ge 1 ] || usage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Return 0 if token exists as a git object, 1 otherwise.
is_git_object() {
	git -C "$REPO_ROOT" cat-file -t "$1" >/dev/null 2>&1
}

# Return 0 if token is reachable from HEAD.
is_reachable() {
	git -C "$REPO_ROOT" merge-base --is-ancestor "$1" HEAD 2>/dev/null
}

# Return the one-line subject for a commit object (works for dangling too).
commit_subject() {
	git -C "$REPO_ROOT" show -s --format="%s" "$1" 2>/dev/null
}

# Try to find a reachable twin by grepping commit subjects.
# For a dangling commit: pass its subject text so we search on meaning.
# For a non-object: pass the raw token to look for literal mentions.
find_twin() {
	local needle="$1"
	# Use -F (fixed string) and --format to avoid shell-glob issues.
	local match
	match=$(git -C "$REPO_ROOT" log --oneline --fixed-strings \
		--grep="$needle" 2>/dev/null | head -1)
	printf '%s' "$match"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

# Counters for the summary line.
total=0
found=0
twin=0
dangling_twin=0
dangling_no_twin=0
no_twin=0

for file in "$@"; do
	if [ ! -f "$file" ]; then
		echo "WARNING: skipping non-regular file: $file" >&2
		continue
	fi

	# Extract every 12–40 char lowercase hex token.
	# grep -oE emits one match per line; we then deduplicate.
	# Exclude tokens that are pure decimal (only [0-9]).
	tokens=$(grep -oE '[0-9a-f]{12,40}' "$file" \
		| grep '[a-f]' \
		| sort -u)

	[ -n "$tokens" ] || continue

	printf '=== %s ===\n' "$file"

	while IFS= read -r token; do
		total=$((total + 1))

		if is_git_object "$token"; then
			if is_reachable "$token"; then
				subject=$(commit_subject "$token")
				printf 'FOUND                  %s  ("%s")\n' "$token" "$subject"
				found=$((found + 1))
			else
				# Dangling: object exists but not reachable.
				subject=$(commit_subject "$token")
				if [ -n "$subject" ]; then
					twin_line=$(find_twin "$subject")
				else
					twin_line=""
				fi
				if [ -n "$twin_line" ]; then
					twin_hash=$(printf '%s' "$twin_line" | cut -d' ' -f1)
					twin_subj=$(printf '%s' "$twin_line" | cut -d' ' -f2-)
					printf 'DANGLING               %s  → %s  ("%s")\n' \
						"$token" "$twin_hash" "$twin_subj"
					dangling_twin=$((dangling_twin + 1))
				else
					printf 'DANGLING-NO-TWIN       %s  (was: "%s")\n' \
						"$token" "${subject:-<unreadable>}"
					dangling_no_twin=$((dangling_no_twin + 1))
				fi
			fi
		else
			# Not an object at all — try literal hash grep in log.
			twin_line=$(find_twin "$token")
			if [ -n "$twin_line" ]; then
				twin_hash=$(printf '%s' "$twin_line" | cut -d' ' -f1)
				twin_subj=$(printf '%s' "$twin_line" | cut -d' ' -f2-)
				printf 'NOT-AN-OBJECT-WITH-TWIN %s  → %s  ("%s")\n' \
					"$token" "$twin_hash" "$twin_subj"
				twin=$((twin + 1))
			else
				printf 'NOT-AN-OBJECT-NO-TWIN  %s\n' "$token"
				no_twin=$((no_twin + 1))
			fi
		fi
	done <<< "$tokens"

	printf '\n'
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '--- summary ---\n'
printf 'total tokens:             %d\n' "$total"
printf 'FOUND (reachable):        %d\n' "$found"
printf 'DANGLING with twin:       %d\n' "$dangling_twin"
printf 'DANGLING-NO-TWIN:         %d\n' "$dangling_no_twin"
printf 'NOT-AN-OBJECT with twin:  %d\n' "$twin"
printf 'NOT-AN-OBJECT-NO-TWIN:    %d\n' "$no_twin"

exit 0
