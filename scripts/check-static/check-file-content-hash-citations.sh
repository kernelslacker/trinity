#!/bin/bash
#
# check-file-content-hash-citations.sh -- detect dangling git-hash citations
# in tracked *.c, *.h, Documentation/*, scripts/*.sh and scripts/**/*.sh files.
#
# The hash citation convention (extended from commit-msg-hash-resolves to
# cover file content) requires that every bare hex token embedded in a source
# or doc file either (a) does not resolve as a git object in this repo, or
# (b) resolves AND is reachable from HEAD.  Class (b-fail) -- token exists as
# a git object but is NOT reachable -- is the dangerous class: `git cat-file
# -t` reports "commit" (looks valid) but the object is a dangling cherry-pick
# orphan pointing at wrong context.
#
# Three outcome categories per token:
#
#   DANGLING  -- git cat-file -t <tok> succeeds AND merge-base --is-ancestor
#                fails.  This is the FAIL class.  The resolver attempts to
#                find a reachable twin by (1) extracting an adjacent
#                ("subject") annotation from the same line, then (2) falling
#                back to scripts/hash-subject-resolver.sh.
#   SKIP      -- git cat-file -t fails (not an object in this repo): stale
#                external reference, pruned object, or example hash.  Counted
#                and printed so the baseline population is auditable.
#   (silent)  -- token exists and is reachable from HEAD.  No output.
#
# Exit 1 if any DANGLING tokens are found; exit 0 otherwise.
#
# Self-exclusion: this script and scripts/hash-subject-resolver.sh are never
# scanned (they legitimately contain hex tokens that exercise these code paths
# and would produce false positives).
#

set -u

NAME="file-content-hash-citations"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESOLVER="$ROOT/scripts/hash-subject-resolver.sh"

# Self-exclusion: canonical paths of files never scanned.
SELF="scripts/check-static/check-file-content-hash-citations.sh"
RESOLVER_REL="scripts/hash-subject-resolver.sh"

fail() {
	echo "FAIL: $NAME: $*"
	exit 1
}

pass() {
	echo "PASS: $NAME: $*"
	exit 0
}

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

is_git_object() {
	git cat-file -t "$1" >/dev/null 2>&1
}

is_reachable() {
	git merge-base --is-ancestor "$1" HEAD 2>/dev/null
}

commit_subject() {
	git show -s --format="%s" "$1" 2>/dev/null
}

# Given a subject string, return "HASH subject" for the unique reachable twin,
# "AMBIGUOUS ..." for multiple matches, or "" for no match.
find_twin() {
	local needle="$1"
	local raw twins=()
	raw=$(git log --format='%H %s' --fixed-strings --grep="$needle" 2>/dev/null)
	[ -n "$raw" ] || { printf ''; return; }
	while IFS= read -r line; do
		local h="${line%% *}" s="${line#* }"
		[ "$s" = "$needle" ] && twins+=("$h")
	done <<< "$raw"
	if [ "${#twins[@]}" -eq 0 ]; then
		printf ''
	elif [ "${#twins[@]}" -eq 1 ]; then
		printf '%s %s' "${twins[0]}" "$needle"
	else
		printf 'AMBIGUOUS'
		local h; for h in "${twins[@]}"; do printf ' %s' "$h"; done
	fi
}

# Extract adjacent ("subject") annotation from a line: TOKEN ("subject text")
extract_adjacent_subject() {
	local token="$1" line="$2"
	printf '%s\n' "$line" \
		| sed -n "s/.*${token} (\"\\([^\"]*\\)\").*/\\1/p" \
		| head -1
}

# ---------------------------------------------------------------------------
# Enumerate files
# ---------------------------------------------------------------------------

mapfile -t tracked_files < <(
	git ls-files '*.c' '*.h' 'Documentation/*' 'scripts/*.sh' 'scripts/**/*.sh' 2>/dev/null \
		| grep -v "^${SELF}$" \
		| grep -v "^${RESOLVER_REL}$"
)

if [ "${#tracked_files[@]}" -eq 0 ]; then
	pass "no tracked files to scan"
fi

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

dangling_count=0
skip_count=0
dangling_detail=""
skip_detail=""

for file in "${tracked_files[@]}"; do
	[ -f "$file" ] || continue

	# Pre-filter: only process lines that contain at least one potential hex
	# token.  This avoids spawning a grep subprocess for every line in large
	# C/H source files (419k lines total) -- only the ~handful of matching
	# lines are processed.
	while IFS= read -r grepline; do
		lineno="${grepline%%:*}"
		line="${grepline#*:}"

		# Extract hex tokens: 12-40 chars, must contain at least one [a-f].
		# Read all matches on this line.
		while IFS= read -r tok; do
			[ -n "$tok" ] || continue

			if is_git_object "$tok"; then
				if ! is_reachable "$tok"; then
					# DANGLING: object exists but not reachable from HEAD.
					dangling_count=$((dangling_count + 1))

					# Try to resolve subject for informative output.
					# Step 1: adjacent annotation on the same line.
					subject=$(extract_adjacent_subject "$tok" "$line")
					# Step 2: fallback to dangling object's own subject.
					if [ -z "$subject" ] && [ -x "$RESOLVER" ]; then
						subject=$(commit_subject "$tok")
					fi
					# Step 3: try to find a reachable twin.
					twin_info=""
					if [ -n "$subject" ]; then
						twin_line=$(find_twin "$subject")
						if [ -n "$twin_line" ] && [[ "$twin_line" != AMBIGUOUS* ]]; then
							twin_hash="${twin_line%% *}"
							twin_info=" → twin: ${twin_hash} (\"${subject}\")"
						elif [[ "$twin_line" == AMBIGUOUS* ]]; then
							twin_info=" → AMBIGUOUS: ${twin_line#AMBIGUOUS }"
						else
							twin_info=" (subject: \"${subject}\", no twin found)"
						fi
					fi

					dangling_detail="${dangling_detail}
  DANGLING citation in ${file}:${lineno}: ${tok}${twin_info}"
				fi
				# else: reachable -- silent pass
			else
				# NOT-AN-OBJECT: stale external reference or example token.
				skip_count=$((skip_count + 1))
				skip_detail="${skip_detail}
  SKIP (not-an-object) ${file}:${lineno}: ${tok}"
			fi

		done < <(printf '%s\n' "$line" | grep -oE '[0-9a-f]{12,40}' | grep '[a-f]' | sort -u)

	done < <(grep -n -E '[0-9a-f]{12,40}' "$file" 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

if [ "$skip_count" -gt 0 ]; then
	printf '%s\n' "  not-an-object baseline (skip_count=${skip_count}):${skip_detail}" >&2
fi

if [ "$dangling_count" -gt 0 ]; then
	{
		echo "  $NAME: ${dangling_count} dangling hash citation(s) in file content"
		echo "  These hashes exist as git objects but are NOT reachable from HEAD."
		echo "  They are dangling objects from cherry-pick rewriting, not the"
		echo "  correct master commits.  Update each citation to the reachable twin"
		echo "  shown above and annotate with the commit subject:"
		echo "    HASH (\"subsystem: brief subject\")"
		printf '%s\n' "${dangling_detail}"
	} >&2
	fail "${dangling_count} dangling hash citation(s) in file content (${skip_count} not-an-object skipped)"
fi

pass "${#tracked_files[@]} files scanned, 0 dangling (${skip_count} not-an-object skipped)"
