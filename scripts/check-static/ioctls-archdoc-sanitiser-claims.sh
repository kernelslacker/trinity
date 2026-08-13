#!/bin/bash
#
# ioctls-archdoc-sanitiser-claims: verify that ioctls/CLAUDE.md does not
# falsely assert a file has "zero custom sanitisers" or "no per-command
# struct fillers" when that file actually contains sanitise_* definitions.
#
# Background: ioctls/CLAUDE.md previously claimed vfio.c and iommufd.c had
# zero custom sanitisers.  Both actually have 17 and 21 sanitise_vfio_* /
# sanitise_iommufd_* functions respectively.  The false doc propagated into
# a 3-agent review finding against already-landed work during a multi-agent review.
#
# Two fail-closed guards (fail-closed against inert-gate and vacuous-pass traps):
#
#   Guard 1 — non-empty seed table.  A seed table with zero rows silently
#   PASSes even if CLAUDE.md is full of false claims.  Assert rows >= 1
#   before scanning.
#
#   Guard 2 — seeded files must have definitions.  After the fix, CLAUDE.md
#   no longer contains the claim pattern for vfio/iommufd, so the pattern
#   scanner has nothing to match.  An intentionally empty match set is only
#   safe if we separately verify that each seeded file still has sanitise_*
#   definitions — a row whose file has zero definitions can never detect a
#   regression (same defect as having no row at all).
#
# Scan logic (Guard 3): search ioctls/CLAUDE.md for the claim pattern
# ("zero custom sanitisers" or "no per-command struct fillers").  For each
# matching context, check whether any seeded filename appears nearby.  If it
# does, and if the file actually has sanitise_* definitions, the doc and the
# code disagree — FAIL.  An empty match set is fine (the fix removed the
# claim) as long as Guards 1 and 2 still fire.

set -u

NAME="ioctls-archdoc-sanitiser-claims"
ROOT="${REPO_ROOT:-$(pwd)}"

ARCHDOC_MD="$ROOT/ioctls/CLAUDE.md"

# Claim patterns that assert a file has no hand-written sanitisers.
CLAIM_PATTERN='zero custom sanitisers|no per-command struct fillers'

# Seed table: files that must have sanitise_* function definitions.
# Add a new row whenever CLAUDE.md is updated to cover a new group.
# NEVER leave this table empty -- that is Guard 1's tripwire.
SEED_FILES=(
	"ioctls/vfio.c"
	"ioctls/iommufd.c"
)

# ── Guard 1: seed table must have >= 1 row ───────────────────────────────────
NROWS="${#SEED_FILES[@]}"
if [ "$NROWS" -lt 1 ]; then
	echo "FAIL: $NAME: seed table is empty (fail-closed guard; add at least one row)" >&2
	exit 1
fi

FAIL=0

# ── Guard 2: each seeded file must have >= 1 sanitise_* definitions ──────────
# If the file has zero definitions the row can never detect a regression
# (the pattern check in Guard 3 would fire, but the definition count check
# would trivially pass -- inverting the logic).
for f in "${SEED_FILES[@]}"; do
	full="$ROOT/$f"
	if [ ! -f "$full" ]; then
		echo "FAIL: $NAME: seeded file not found: $f" >&2
		FAIL=1
		continue
	fi
	count=$(grep -c '^static void sanitise' "$full" 2>/dev/null) || count=0
	if [ "$count" -lt 1 ]; then
		echo "FAIL: $NAME: $f has no 'static void sanitise*' definitions" \
		     "(seeded row can never fire; remove the row or add definitions)" >&2
		FAIL=1
	fi
done

# ── Guard 3: CLAUDE.md must exist ────────────────────────────────────────────
if [ ! -f "$ARCHDOC_MD" ]; then
	echo "FAIL: $NAME: $ARCHDOC_MD not found" >&2
	exit 1
fi

# ── Guard 3 (cont): scan for the claim pattern ───────────────────────────────
# For each matching line in CLAUDE.md, check whether any seeded filename
# appears within 4 lines of context.  If yes and the file has sanitisers,
# the doc is lying -- FAIL.
claim_hits=$(grep -nE "$CLAIM_PATTERN" "$ARCHDOC_MD" 2>/dev/null) || claim_hits=""

if [ -n "$claim_hits" ]; then
	for f in "${SEED_FILES[@]}"; do
		[ -f "$ROOT/$f" ] || continue
		bn=$(basename "$f")
		# Collect line numbers that match the claim pattern.
		while IFS=: read -r lineno _rest; do
			# Extract a window of ±4 lines around the match.
			start=$(( lineno - 4 ))
			[ "$start" -lt 1 ] && start=1
			end=$(( lineno + 4 ))
			window=$(sed -n "${start},${end}p" "$ARCHDOC_MD" 2>/dev/null)
			if printf '%s\n' "$window" | grep -qF "$bn"; then
				count=$(grep -c '^static void sanitise' "$ROOT/$f" 2>/dev/null) \
				    || count=0
				if [ "$count" -gt 0 ]; then
					echo "FAIL: $NAME: ioctls/CLAUDE.md line $lineno" \
					     "claims $bn has zero custom sanitisers" \
					     "but $ROOT/$f has $count sanitise_* definition(s)" >&2
					FAIL=1
				fi
			fi
		done <<< "$(printf '%s\n' "$claim_hits" | cut -d: -f1)"
	done
fi

# ── Result ────────────────────────────────────────────────────────────────────
if [ "$FAIL" -ne 0 ]; then
	echo "FAIL: $NAME"
	exit 1
fi

echo "PASS: $NAME: ${NROWS} seeded file(s) verified, no false zero-sanitiser claim in ioctls/CLAUDE.md"
exit 0
