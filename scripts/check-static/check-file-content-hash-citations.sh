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
#   (silent)  -- token exists and is reachable from HEAD AND carries an
#                adjacent ("subject") annotation.  No output.
#   BARE      -- token exists and is reachable from HEAD but lacks an adjacent
#                ("subject") annotation within 80 chars.  Entries listed in
#                check-file-content-hash-citations-bare.baseline are reported
#                ADVISORY only; any bare internal citation not in the baseline
#                is a FAIL.  This is a descend-only ratchet: fixing a citation
#                removes its line from the baseline; adding a new bare one
#                fails immediately.
#
# Exit 1 if any DANGLING or new-BARE tokens are found; exit 0 otherwise.
# Advisory warnings (upstream-prefix and baseline bare) are non-fatal.
#
# Self-exclusion: this script and scripts/hash-subject-resolver.sh are never
# scanned (they legitimately contain hex tokens that exercise these code paths
# and would produce false positives).

set -u

# Memoisation cache for classify_notanobject_token() (declared after set -u
# so -u applies inside the function body; the array itself is global).
declare -A _notanobj_cls_cache

# Baseline set for bare internal citations (file:hashtoken -> 1).
declare -A _bare_baseline
# Tracks which baseline entries were matched during this scan (for stale detection).
declare -A _bare_baseline_seen

# Baseline set for subject-annotation mismatches (file:hashtoken -> 1).
declare -A _subject_baseline
# Tracks which subject baseline entries were matched during this scan.
declare -A _subject_baseline_seen

NAME="file-content-hash-citations"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
RESOLVER="$ROOT/scripts/hash-subject-resolver.sh"
BARE_BASELINE="$ROOT/scripts/check-static/check-file-content-hash-citations-bare.baseline"
SUBJECT_BASELINE="$ROOT/scripts/check-static/check-file-content-hash-citations-subject.baseline"

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

# Extract adjacent ("subject") annotation from a source line.
#
# Usage: extract_adjacent_subject TOKEN LINE [FILE LINENO]
#
# First attempts single-line extraction for the canonical form:
#   TOKEN ("subject text")
# If that fails and an unclosed (" is present after TOKEN, reads the next
# source line (FILE:LINENO+1), strips its comment leader, joins the two lines,
# and retries.  This handles wrapped annotations where the close-quote sits on
# a continuation line.
extract_adjacent_subject() {
	local token="$1" line="$2" file="${3:-}" lineno="${4:-}"
	# Try single-line extraction first.
	local subj
	subj=$(printf '%s\n' "$line" \
		| sed -n "s/.*${token} (\"\\([^\"]*\\)\").*/\\1/p" \
		| head -1)
	if [ -n "$subj" ]; then
		printf '%s' "$subj"
		return
	fi
	# If FILE and LINENO are available and the line has an unclosed annotation
	# (open-paren + open-quote after TOKEN but no matching close-quote), try
	# joining with the next source line.
	if [ -n "$file" ] && [ -n "$lineno" ] && \
			printf '%s\n' "$line" | grep -qE "${token}.{0,80}\(\"[^\"]*$"; then
		local nextline
		nextline=$(sed -n "$((lineno + 1))p" "$file" 2>/dev/null)
		# Strip comment leaders: ' * ', '# ', '//', etc.
		nextline=$(printf '%s\n' "$nextline" \
			| sed 's/^[[:space:]]*[*#/]\{1,2\}[[:space:]]*//')
		# Join and retry extraction; normalise runs of whitespace to a single space.
		subj=$(printf '%s %s\n' "$line" "$nextline" \
			| sed -n "s/.*${token} (\"\\([^\"]*\\)\").*/\\1/p" \
			| head -1 \
			| tr -s ' ')
		printf '%s' "$subj"
		return
	fi
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
bare_advisory_count=0
bare_fail_count=0
subject_mismatch_count=0
subject_mismatch_advisory_count=0
subject_unvalidated_count=0
dangling_detail=""
skip_detail=""
bare_fail_detail=""
subject_mismatch_detail=""

# Load bare-citation baseline.
if [ -f "$BARE_BASELINE" ]; then
	while IFS= read -r _bline; do
		[[ -z "$_bline" || "$_bline" == \#* ]] && continue
		if [[ -v _bare_baseline["$_bline"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $_bline" >&2
			exit 1
		fi
		_bare_baseline["$_bline"]=1
	done < "$BARE_BASELINE"
fi

# Load subject-mismatch baseline.
if [ -f "$SUBJECT_BASELINE" ]; then
	while IFS= read -r _sline; do
		[[ -z "$_sline" || "$_sline" == \#* ]] && continue
		if [[ -v _subject_baseline["$_sline"] ]]; then
			echo "FAIL: $NAME: duplicate subject-baseline entry: $_sline" >&2
			exit 1
		fi
		_subject_baseline["$_sline"]=1
	done < "$SUBJECT_BASELINE"
fi

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
					# Step 1: adjacent annotation (single-line or wrapped).
					subject=$(extract_adjacent_subject "$tok" "$line" "$file" "$lineno")
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
				else
					# Reachable internal hash.  Convention requires an adjacent
					# ("subject") annotation on the same line within 80 chars
					# after the hash token.
					if ! printf '%s\n' "$line" | grep -qE "${tok}.{0,80}\\(\""; then
						_filehash="${file}:${tok}"
						if [[ -v _bare_baseline["$_filehash"] ]]; then
							bare_advisory_count=$((bare_advisory_count + 1))
							_bare_baseline_seen["$_filehash"]=1
						else
							bare_fail_count=$((bare_fail_count + 1))
							bare_fail_detail="${bare_fail_detail}
  BARE (no subject) citation in ${file}:${lineno}: ${tok}"
						fi
					else
						# Annotation present: validate the annotated subject against
						# the real commit subject via git log.
						annotated_subj=$(extract_adjacent_subject "$tok" "$line" "$file" "$lineno")
						if [ -n "$annotated_subj" ]; then
							real_subj=$(git log -1 --pretty=%s "$tok" 2>/dev/null)
							# Normalise runs of whitespace before comparing (wrapped
							# annotations may reconstruct with extra internal spaces).
							norm_ann=$(printf '%s' "$annotated_subj" | tr -s ' ')
							norm_real=$(printf '%s' "$real_subj" | tr -s ' ')
							if [ "$norm_ann" != "$norm_real" ]; then
								_filehash="${file}:${tok}"
								if [[ -v _subject_baseline["$_filehash"] ]]; then
									subject_mismatch_advisory_count=$((subject_mismatch_advisory_count + 1))
									_subject_baseline_seen["$_filehash"]=1
								else
									subject_mismatch_count=$((subject_mismatch_count + 1))
									subject_mismatch_detail="${subject_mismatch_detail}
  SUBJECT MISMATCH in ${file}:${lineno}: ${tok}
    annotated: \"${annotated_subj}\"
    real:      \"${real_subj}\""
								fi
							fi
							# else: annotation matches real subject -- silent pass
						else
							# Presence check passed but extraction returned empty --
							# subject could not be recovered even after trying to join
							# a continuation line.  Count so the pass line never
							# silently claims full coverage.
							subject_unvalidated_count=$((subject_unvalidated_count + 1))
						fi
					fi
				fi
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
# Stale baseline entries: entries in the baseline whose file:hash no longer
# appears anywhere in the scanned tree.
# ---------------------------------------------------------------------------

stale_count=0
stale_detail=""
for _bkey in "${!_bare_baseline[@]}"; do
	if [[ ! -v _bare_baseline_seen["$_bkey"] ]]; then
		stale_count=$((stale_count + 1))
		stale_detail="${stale_detail}
  STALE bare baseline entry (file+hash no longer in tree): ${_bkey}"
	fi
done

for _bkey in "${!_subject_baseline[@]}"; do
	if [[ ! -v _subject_baseline_seen["$_bkey"] ]]; then
		stale_count=$((stale_count + 1))
		stale_detail="${stale_detail}
  STALE subject-mismatch baseline entry (file+hash no longer in tree): ${_bkey}"
	fi
done

if [ "$stale_count" -gt 0 ]; then
	{
		echo "  $NAME: ${stale_count} stale/orphaned baseline entry(ies) -- hash token no longer present in tree"
		echo "  Remove the corresponding line(s) from the relevant baseline file."
		printf '%s\n' "${stale_detail}"
	} >&2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

if [ "$skip_count" -gt 0 ]; then
	printf '%s\n' "  not-an-object baseline (skip_count=${skip_count}):${skip_detail}" >&2
fi

if [ "$bare_fail_count" -gt 0 ]; then
	{
		echo "  $NAME: ${bare_fail_count} new bare internal citation(s) lack (\"subject\") annotation"
		echo "  Add a subject annotation on the same line within 80 chars after the hash:"
		echo "    HASH (\"subsystem: brief subject\")"
		echo "  Or add the entry to the bare baseline if this is an intentional exception."
		printf '%s\n' "${bare_fail_detail}"
	} >&2
fi

if [ "$subject_mismatch_count" -gt 0 ]; then
	{
		echo "  $NAME: ${subject_mismatch_count} subject annotation(s) do not match the real commit subject"
		echo "  Fix the annotation to match \`git log -1 --pretty=%s <hash>\`:"
		echo "    HASH (\"subsystem: exact commit subject\")"
		echo "  Or add the entry to check-file-content-hash-citations-subject.baseline."
		printf '%s\n' "${subject_mismatch_detail}"
	} >&2
fi

SCRIPT_DIR="$ROOT/scripts/check-static"
advisory_baseline_file="$SCRIPT_DIR/check-file-content-hash-citations-advisory.baseline"
if [ ! -r "$advisory_baseline_file" ]; then
	fail "advisory baseline file not found: $advisory_baseline_file"
fi
advisory_baseline=$(< "$advisory_baseline_file")

if [ "$dangling_count" -gt 0 ] || [ "$bare_fail_count" -gt 0 ] || [ "$subject_mismatch_count" -gt 0 ]; then
	if [ "$dangling_count" -gt 0 ]; then
		{
			echo "  $NAME: ${dangling_count} dangling hash citation(s) in file content"
			echo "  These hashes include live-dangling objects (unreachable from HEAD)"
			echo "  and GC'd orphans identified by a unique subject-resolvable twin."
			echo "  Update each citation to the reachable twin and annotate:"
			echo "    HASH (\"subsystem: brief subject\")"
			printf '%s\n' "${dangling_detail}"
		} >&2
	fi
	fail "${dangling_count} dangling + ${bare_fail_count} new-bare + ${subject_mismatch_count} subject-mismatch citation(s) (subject-unvalidated=${subject_unvalidated_count}, ${skip_count} skipped, advisory: ${advisory_count} upstream-prefix, ${bare_advisory_count} baseline-bare, ${subject_mismatch_advisory_count} baseline-subject-mismatch, ${stale_count} stale-baseline)"
fi

# Ratchet: advisory count must not grow beyond the frozen baseline.
if [ "$advisory_count" -gt "$advisory_baseline" ]; then
	fail "advisory upstream-hash tokens grew: ${advisory_count} > baseline ${advisory_baseline} — add upstream: prefix or update baseline"
fi

pass "${#tracked_files[@]} files scanned, 0 dangling, 0 new-bare, 0 subject-mismatch, subject-unvalidated=${subject_unvalidated_count} (${skip_count} not-an-object skipped, advisory: ${advisory_count}/${advisory_baseline} upstream-hash token(s) lack upstream: prefix, ${bare_advisory_count} baseline bare citation(s), ${subject_mismatch_advisory_count} baseline subject-mismatch(es), ${stale_count} stale-baseline)"
