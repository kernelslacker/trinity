#!/bin/bash
#
# commit-msg-hash-citations-informal.sh -- detect bare-informal hash
# citations in commit messages of commits in the range being gated.
#
# The citation convention (Documentation/check-static.md) requires that
# every in-repo hash cited in a commit message carry the quoted-subject
# annotation form:
#
#   HASH ("subsystem: exact commit subject")
#
# A bare-informal citation uses unquoted text in the parens:
#
#   HASH (some description without quotes)
#
# This form is WRONG: it cannot be mechanically validated against the
# real commit subject, it survives cherry-pick rewriting invisibly, and
# it attributes work to the wrong description when the subject has
# drifted.  The gate flags every occurrence in newly-added commit
# messages that is not listed in the commit-hash-keyed baseline.
#
# Baseline: entries are the full SHA1 of commits whose messages contain
# a known pre-existing bare-informal citation that cannot be amended
# (history is immutable).  Keyed on commit SHA, not line content, so
# the baseline is immune to cherry-pick rewriting.  Pre-existing entries
# are reported as ADVISORY; any new bare-informal citation not in the
# baseline exits 1.
#
# Range: origin/master..HEAD, falling back to HEAD~200..HEAD when
# origin/master is not available or equals HEAD (same fallback logic as
# scripts/commit-msg-hash-resolves.sh).

set -u

NAME="commit-msg-hash-citations-informal"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASELINE="$ROOT/scripts/check-static/${NAME}.baseline"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

fail() { echo "FAIL: $NAME: $*"; exit 1; }
pass() { echo "PASS: $NAME: $*"; exit 0; }

# ---------------------------------------------------------------------------
# Range
# ---------------------------------------------------------------------------

if git rev-parse --verify origin/master >/dev/null 2>&1 \
	&& [ "$(git rev-parse origin/master)" != "$(git rev-parse HEAD)" ]; then
	RANGE="origin/master..HEAD"
else
	RANGE="HEAD~200..HEAD"
fi

# ---------------------------------------------------------------------------
# Baseline (commit SHAs whose bare-informal citations are pre-existing)
# ---------------------------------------------------------------------------

declare -A _baseline
if [ -f "$BASELINE" ]; then
	while IFS= read -r bline; do
		[[ -z "$bline" || "$bline" == \#* ]] && continue
		# Resolve abbreviated or full SHA; warn and skip unresolvable entries.
		full=$(git rev-parse --verify "${bline%% *}" 2>/dev/null) || {
			echo "WARNING: $NAME: baseline entry unresolvable, skipping: ${bline%% *}" >&2
			continue
		}
		if [[ -v _baseline["$full"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $full (from: $bline)" >&2
			exit 1
		fi
		_baseline["$full"]=1
	done < "$BASELINE"
fi

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

# Bare-informal pattern: hex token (12-40 chars, at least one a-f)
# followed by ( description-without-leading-quote ).
# Description must be 3+ chars and must not begin with a double-quote.
# Capped at 100 chars to avoid matching prose sentences that happen to
# contain a hash and a parenthesised clause after line-joining; real
# commit subjects almost never exceed 72 chars.
# Tokens preceded by "upstream:" (with or without space after :) are
# elided before pattern matching -- they are external references.
BARE_RE='[0-9a-f]{12,40} \([^"(][^)]{2,100}\)'

fail_count=0
advisory_count=0
fail_detail=""
advisory_detail=""

while IFS= read -r full_hash; do
	[ -n "$full_hash" ] || continue

	body=$(git log -1 --format="%B" "$full_hash" 2>/dev/null)
	[ -n "$body" ] || continue

	# Collapse the commit body to a single line so that citations that
	# wrap across two lines (e.g. long descriptions folded at the terminal
	# width) are still caught by the single-pass regex.  Normalise runs of
	# whitespace introduced by the join to a single space.
	flat=$(printf '%s\n' "$body" | tr '\n' ' ' | tr -s ' ')

	# Elide upstream: tokens so they don't trip the pattern.
	elided=$(printf '%s\n' "$flat" \
		| sed -E 's/upstream:[[:space:]]*[0-9a-f]{12,40}/UPSTREAM_ELIDED/g')

	# Find all bare-informal hits across the whole (flattened) message.
	hits=$(printf '%s\n' "$elided" | grep -oE "$BARE_RE" \
		| grep -E '^[0-9a-f]*[a-f][0-9a-f]* ' \
		| sort -u)

	[ -n "$hits" ] || continue

	short=$(git log -1 --format="%h %s" "$full_hash" 2>/dev/null)
	hit_lines=$(printf '%s\n' "$hits" | sed 's/^/    /')

	if [[ -v _baseline["$full_hash"] ]]; then
		advisory_count=$((advisory_count + 1))
		advisory_detail="${advisory_detail}
  ADVISORY (baselined) ${short}:
${hit_lines}"
	else
		fail_count=$((fail_count + 1))
		fail_detail="${fail_detail}
  BARE-INFORMAL ${short}:
${hit_lines}"
	fi

done < <(git log --format="%H" "$RANGE" 2>/dev/null)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

if [ "$fail_count" -gt 0 ]; then
	{
		echo "  $NAME: $fail_count commit(s) with bare-informal hash citation(s)"
		echo "  range: $RANGE"
		echo "  Bare-informal form: HASH (description text)"
		echo "  Required form:      HASH (\"exact commit subject\")"
		echo "  Run: git log -1 --pretty=%s <hash>  to find the exact subject."
		echo "  Then update the citation to use the quoted-subject form."
		printf '%s\n' "$fail_detail"
	} >&2
	fail "$fail_count commit(s) with bare-informal citation(s) in range $RANGE (${advisory_count} baselined)"
fi

pass "range $RANGE: 0 bare-informal (${advisory_count} pre-existing baselined)"
