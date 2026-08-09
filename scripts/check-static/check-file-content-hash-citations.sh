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
# Four outcome categories per token:
#
#   DANGLING  -- git cat-file -t <tok> succeeds AND merge-base --is-ancestor
#                fails.  This is the FAIL class.  The resolver attempts to
#                find a reachable twin by (1) extracting an adjacent
#                ("subject") annotation from the same line, then (2) falling
#                back to scripts/hash-subject-resolver.sh.
#   DANGLING  -- (GC'd orphan sub-class) git cat-file -t fails AND the token
#      (GC'd)    is exactly 12 hex chars AND git log history contains an
#                informal citation TOKEN (subject) for this hash WITHOUT an
#                adjacent "upstream" or "commit" keyword, AND that subject
#                resolves to a unique reachable twin via prefix match.  These
#                are cherry-pick orphans GC'd before the gate ran.  Same FAIL
#                class as the live-dangling case above.
#   ADVISORY  -- exactly-12-hex token that is not an object and not a
#                confirmed GC'd orphan, but git log history or the source
#                line's context identifies it as an upstream kernel commit
#                reference lacking the upstream: prefix convention.  Non-fatal;
#                reported in the pass line so the adoption scope is visible.
#   SKIP      -- git cat-file -t fails (not an object in this repo) and the
#                token is confirmed external data (no upstream/commit context
#                in history or source line) or is properly prefixed with
#                upstream:.  Counted and printed to stderr so the baseline
#                population is auditable.
#   (silent)  -- token exists and is reachable from HEAD.  No output.
#
# Exit 1 if any DANGLING tokens are found; exit 0 otherwise.
# Advisory warnings are non-fatal; the gate passes with advisory > 0.
#
# Self-exclusion: this script and scripts/hash-subject-resolver.sh are never
# scanned (they legitimately contain hex tokens that exercise these code paths
# and would produce false positives).

set -u

# Memoisation cache for classify_notanobject_token() (declared after set -u
# so -u applies inside the function body; the array itself is global).
declare -A _notanobj_cls_cache

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

# ---------------------------------------------------------------------------
# Not-an-object token classifier
# ---------------------------------------------------------------------------
#
# classify_notanobject_token TOKEN
#
# Returns one of:
#   INTERNAL  -- GC'd cherry-pick orphan with a unique reachable twin.
#                The token appeared in a git log commit body using the
#                informal citation form  TOKEN (description)  WITHOUT a
#                leading double-quote inside the parens AND without an
#                adjacent "upstream" or "commit" keyword, AND the extracted
#                description resolves to exactly one reachable commit via a
#                prefix subject match.
#   EXTERNAL  -- Token is present in git log history but does not satisfy
#                the INTERNAL criteria (formal double-quoted annotation, or
#                "upstream"/"commit" context, or ambiguous/missing twin).
#                Treated as an upstream or external reference.
#   DATA      -- Token has no entry in git log history at all.  It is a
#                data constant, magic number, or upstream hash that was never
#                mentioned in any trinity commit message.
#
# Results are memoised in _notanobj_cls_cache.
classify_notanobject_token() {
	local tok="$1"

	if [[ -v _notanobj_cls_cache["$tok"] ]]; then
		printf '%s' "${_notanobj_cls_cache[$tok]}"
		return
	fi

	local result="DATA"

	# Search all reachable commit bodies for this token.
	local collapsed
	collapsed=$(git log --fixed-strings --grep="$tok" --format='%B' 2>/dev/null \
		| tr '\n' ' ')

	if [ -n "$collapsed" ]; then
		# Look for the informal internal citation pattern:
		#   TOKEN (description-without-leading-double-quote)
		# with at most 60 preceding chars (for the upstream/commit check).
		# Formal convention citations use TOKEN ("subject") with a leading
		# double-quote; those are always EXTERNAL.
		local ctx
		ctx=$(printf '%s\n' "$collapsed" \
			| grep -oE ".{0,60}${tok} \([^\"][^)]{2,79}\)" \
			| head -1)

		if [ -n "$ctx" ] \
				&& ! printf '%s\n' "$ctx" | grep -qiE '\b(upstream|commit)\b'; then
			# Informal citation without upstream/commit context.
			# Extract the description from the parens.
			local subj
			subj=$(printf '%s\n' "$ctx" \
				| sed -n "s/.*${tok} (\([^)]*\)).*/\1/p" \
				| head -1)

			if [ -n "$subj" ]; then
				# Attempt prefix-based twin lookup: any reachable commit
				# whose subject starts with the extracted description.
				local twin_count=0 twin_hash=""
				while IFS= read -r tline; do
					local th ts
					th="${tline%% *}" ts="${tline#* }"
					if [[ "$ts" == "$subj"* ]]; then
						twin_count=$((twin_count + 1))
						twin_hash="$th"
					fi
				done < <(git log --format='%H %s' --fixed-strings \
					--grep="$subj" 2>/dev/null)
				if [ "$twin_count" -eq 1 ]; then
					result="INTERNAL"
				else
					result="EXTERNAL"
				fi
			else
				result="EXTERNAL"
			fi
		else
			# Formal convention citation or upstream/commit context.
			result="EXTERNAL"
		fi
	fi

	_notanobj_cls_cache["$tok"]="$result"
	printf '%s' "$result"
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
advisory_count=0
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
				# NOT-AN-OBJECT: not a git object in this repo.
				# Split into three buckets by token shape and git-log context.
				if [[ ${#tok} -ne 12 ]]; then
					# Not citation-shaped (16-char RNG vectors, 64-char full
					# hashes, address constants longer than 12 hex): skip.
					skip_count=$((skip_count + 1))
					skip_detail="${skip_detail}
  SKIP (not-an-object, non-12) ${file}:${lineno}: ${tok}"
				else
					# Exactly 12 hex: citation-shaped.
					# (a) Properly prefixed upstream: citation — silent skip.
					if printf '%s\n' "$line" \
							| grep -qE "upstream:[[:space:]]*${tok}"; then
						skip_count=$((skip_count + 1))
						skip_detail="${skip_detail}
  SKIP (upstream: prefixed) ${file}:${lineno}: ${tok}"
					else
						notanobj_cls=$(classify_notanobject_token "$tok")
						case "$notanobj_cls" in
						INTERNAL)
							# GC'd orphan with unique reachable twin — FAIL.
							dangling_count=$((dangling_count + 1))
							dangling_detail="${dangling_detail}
  DANGLING (GC'd orphan) citation in ${file}:${lineno}: ${tok}"
							;;
						EXTERNAL)
							# Known external/upstream hash; lacks upstream: prefix.
							advisory_count=$((advisory_count + 1))
							;;
						DATA)
							# Not in git log.  If the source line has an explicit
							# "upstream" or "commit" keyword it is a bare upstream
							# reference; flag advisory.  Otherwise treat as a data
							# constant and skip silently.
							if printf '%s\n' "$line" \
									| grep -qiE '\b(upstream|commit)\b'; then
								advisory_count=$((advisory_count + 1))
							else
								skip_count=$((skip_count + 1))
								skip_detail="${skip_detail}
  SKIP (not-an-object, data) ${file}:${lineno}: ${tok}"
							fi
							;;
						esac
					fi
				fi
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
		echo "  These hashes include live-dangling objects (unreachable from HEAD)"
		echo "  and GC'd orphans identified by a unique subject-resolvable twin."
		echo "  Update each citation to the reachable twin and annotate:"
		echo "    HASH (\"subsystem: brief subject\")"
		printf '%s\n' "${dangling_detail}"
	} >&2
	fail "${dangling_count} dangling hash citation(s) in file content (${skip_count} not-an-object skipped, advisory: ${advisory_count} upstream-hash token(s) lack upstream: prefix)"
fi

pass "${#tracked_files[@]} files scanned, 0 dangling (${skip_count} not-an-object skipped, advisory: ${advisory_count} upstream-hash token(s) lack upstream: prefix)"
