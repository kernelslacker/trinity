#!/bin/bash
#
# hash-subject-resolver.sh -- resolve stale hash citations to reachable twins.
#
# Usage:
#   hash-subject-resolver.sh <file> [<file>...]
#   hash-subject-resolver.sh <rev-range>          (e.g. HEAD~50..HEAD)
#
# For each 12–40 character lowercase hex token found in the given files or
# commit messages, attempts to resolve it to a reachable commit in this repo.
# The cherry-pick workflow rewrites every SHA, so any hash a committer embeds
# in a message or queue document stales the moment its ancestors are amended.
# This tool finds the surviving twin by matching commit subjects.
#
# Output categories (one line per unique token per file/commit):
#
#   FOUND                    hash is reachable from HEAD; subject printed
#   NOT-AN-OBJECT-WITH-TWIN  hash is not in the object store; a reachable
#                            commit with a matching subject was found
#   NOT-AN-OBJECT-NO-TWIN    hash is not in the object store; no twin found
#   DANGLING                 hash is in the object store but unreachable from
#                            HEAD; a reachable twin with the same subject found
#   DANGLING-NO-TWIN         dangling object; no reachable twin found
#   AMBIGUOUS                more than one reachable commit shares the subject;
#                            all candidate hashes are listed
#
# The script prints a rewrite map to stdout and exits 0 in all cases.
# It is an informational / repair-prep tool, not a build gate.
#
# Convention: every hash cited in a commit message, queue row, or review
# document should be accompanied by its commit subject in the form:
#   abc123def456 ("check-static: add …")
# The subject survives cherry-pick rewriting; the bare hash does not.
# Without a cited subject in this form, a NOT-AN-OBJECT token cannot be
# resolved and is reported as NOT-AN-OBJECT-NO-TWIN.

set -u

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

usage() {
	echo "Usage: $0 <file> [<file>...] | <rev-range>" >&2
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

# Try to find a reachable twin by exact subject match.
#
# needle must be the commit subject text (not a raw hash).  Candidates are
# found via --grep (fixed-string), then filtered to only those whose own
# subject (%s) exactly equals needle.  This excludes citers: a commit that
# merely references the needle in its body will have a different subject,
# so it is filtered out.
#
# Returns one of:
#   "HASH subject"          — exactly one exact-subject match
#   "AMBIGUOUS HASH1 HASH2…" — more than one exact-subject match
#   ""                      — no non-citer match
find_twin() {
	local needle="$1"

	# Collect all commits whose message mentions needle (fixed-string).
	# We get both hash and subject so we can compare subjects exactly.
	local raw
	raw=$(git -C "$REPO_ROOT" log --format='%H %s' --fixed-strings \
		--grep="$needle" 2>/dev/null)

	[ -n "$raw" ] || { printf ''; return; }

	# Filter to exact subject matches only.  A citer's subject will differ
	# from needle; a twin's subject will equal needle exactly.
	local twins=()
	while IFS= read -r line; do
		local h s
		h="${line%% *}"
		s="${line#* }"
		[ "$s" = "$needle" ] && twins+=("$h")
	done <<< "$raw"

	if [ "${#twins[@]}" -eq 0 ]; then
		printf ''
	elif [ "${#twins[@]}" -eq 1 ]; then
		printf '%s %s' "${twins[0]}" "$needle"
	else
		# More than one reachable commit has this exact subject — ambiguous.
		printf 'AMBIGUOUS'
		local h
		for h in "${twins[@]}"; do printf ' %s' "$h"; done
	fi
}

# Extract the cited subject from content for a given token.
# Looks for the convention form: TOKEN ("subject").
# Returns the subject string, or empty if no such annotation is present.
extract_cited_subject() {
	local token="$1" content="$2"
	printf '%s\n' "$content" \
		| grep -F "$token" \
		| sed -n "s/.*${token} (\"\\([^\"]*\\)\").*/\\1/p" \
		| head -1
}

# ---------------------------------------------------------------------------
# Per-content processor (shared by file mode and range/commit mode)
# label   = display name (filename or "commit HASH")
# content = the text to scan
# citing_hash = optional commit hash for context (empty in file mode)
# ---------------------------------------------------------------------------
process_content() {
	local label="$1" content="$2"

	# Extract every 12–40 char lowercase hex token; deduplicate.
	# Exclude pure-decimal tokens (no [a-f]).
	local tokens
	tokens=$(printf '%s\n' "$content" \
		| grep -oE '[0-9a-f]{12,40}' \
		| grep '[a-f]' \
		| sort -u)

	[ -n "$tokens" ] || return

	printf '=== %s ===\n' "$label"

	while IFS= read -r token; do
		total=$((total + 1))

		if is_git_object "$token"; then
			if is_reachable "$token"; then
				subject=$(commit_subject "$token")
				printf 'FOUND                   %s  ("%s")\n' "$token" "$subject"
				found=$((found + 1))
			else
				# Dangling: object exists but not reachable from HEAD.
				# RC verified this path is sound — do not alter its logic.
				subject=$(commit_subject "$token")
				if [ -n "$subject" ]; then
					twin_line=$(find_twin "$subject")
				else
					twin_line=""
				fi
				if [ -z "$twin_line" ]; then
					printf 'DANGLING-NO-TWIN        %s  (was: "%s")\n' \
						"$token" "${subject:-<unreadable>}"
					dangling_no_twin=$((dangling_no_twin + 1))
				elif [[ "$twin_line" == AMBIGUOUS* ]]; then
					printf 'AMBIGUOUS               %s  (was: "%s")  candidates: %s\n' \
						"$token" "${subject:-<unreadable>}" "${twin_line#AMBIGUOUS }"
					ambiguous=$((ambiguous + 1))
				else
					twin_hash=$(printf '%s' "$twin_line" | cut -d' ' -f1)
					twin_subj=$(printf '%s' "$twin_line" | cut -d' ' -f2-)
					printf 'DANGLING                %s  → %s  ("%s")\n' \
						"$token" "$twin_hash" "$twin_subj"
					dangling_twin=$((dangling_twin + 1))
				fi
			fi
		else
			# Not an object at all.
			# Parse the adjacent ("subject") from the citation convention:
			#   TOKEN ("some subject")
			# Without this annotation there is no reliable way to find a twin —
			# grepping for the raw hash only ever returns citers (the commits
			# that cite the hash, not the commit the hash identified).
			local cited_subj
			cited_subj=$(extract_cited_subject "$token" "$content")

			if [ -z "$cited_subj" ]; then
				# Old-style bare citation: no subject available.  Report
				# honestly rather than returning a citer as a false twin.
				printf 'NOT-AN-OBJECT-NO-TWIN   %s  (no subject annotation)\n' "$token"
				no_twin=$((no_twin + 1))
			else
				twin_line=$(find_twin "$cited_subj")
				if [ -z "$twin_line" ]; then
					printf 'NOT-AN-OBJECT-NO-TWIN   %s  (subject: "%s", no twin found)\n' \
						"$token" "$cited_subj"
					no_twin=$((no_twin + 1))
				elif [[ "$twin_line" == AMBIGUOUS* ]]; then
					printf 'AMBIGUOUS               %s  (subject: "%s")  candidates: %s\n' \
						"$token" "$cited_subj" "${twin_line#AMBIGUOUS }"
					ambiguous=$((ambiguous + 1))
				else
					twin_hash=$(printf '%s' "$twin_line" | cut -d' ' -f1)
					twin_subj=$(printf '%s' "$twin_line" | cut -d' ' -f2-)
					printf 'NOT-AN-OBJECT-WITH-TWIN %s  → %s  ("%s")\n' \
						"$token" "$twin_hash" "$twin_subj"
					twin=$((twin + 1))
				fi
			fi
		fi
	done <<< "$tokens"

	printf '\n'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Counters for the summary line.
total=0
found=0
twin=0
dangling_twin=0
dangling_no_twin=0
no_twin=0
ambiguous=0

# Detect whether the first argument is a git rev-range (contains '..').
# If so, scan every commit message in the range.
if [[ "$1" == *..* ]] && [ "$#" -eq 1 ]; then
	range="$1"
	# Enumerate commits in the range (oldest → newest for readability).
	commit_list=$(git -C "$REPO_ROOT" log --format='%H' --reverse "$range" 2>/dev/null)
	if [ -z "$commit_list" ]; then
		echo "WARNING: no commits found in range: $range" >&2
		exit 0
	fi
	while IFS= read -r chash; do
		cmsg=$(git -C "$REPO_ROOT" log --format='%B' -n1 "$chash" 2>/dev/null)
		csubj=$(git -C "$REPO_ROOT" log --format='%s' -n1 "$chash" 2>/dev/null)
		process_content "commit ${chash} (${csubj})" "$cmsg"
	done <<< "$commit_list"
else
	# File mode: each argument is a path to scan.
	for file in "$@"; do
		if [ ! -f "$file" ]; then
			echo "WARNING: skipping non-regular file: $file" >&2
			continue
		fi
		fcontent=$(cat "$file")
		process_content "$file" "$fcontent"
	done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '%s\n' '--- summary ---'
printf 'total tokens:             %d\n' "$total"
printf 'FOUND (reachable):        %d\n' "$found"
printf 'DANGLING with twin:       %d\n' "$dangling_twin"
printf 'DANGLING-NO-TWIN:         %d\n' "$dangling_no_twin"
printf 'NOT-AN-OBJECT with twin:  %d\n' "$twin"
printf 'NOT-AN-OBJECT-NO-TWIN:    %d\n' "$no_twin"
printf 'AMBIGUOUS:                %d\n' "$ambiguous"

exit 0
