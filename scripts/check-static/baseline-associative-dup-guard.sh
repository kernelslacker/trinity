#!/bin/bash
#
# baseline-associative-dup-guard.sh -- assert that every script under
# scripts/check-static/ that loads a baseline into a declare -A array
# via a while IFS= read loop protects each insert with a [[ -v ]] dup
# guard.
#
# A loader is any *.sh in scripts/check-static/ that contains both
# "declare -A" and "while IFS= read".  Loaders that lack a [[ -v ]]
# guard anywhere in the file silently overwrite on duplicate keys,
# turning baseline duplication bugs into invisible semantic corruption.
#
# Gate logic:
#   FAIL  -- loader has no [[ -v ]] guard and is not in the baseline.
#            This fires immediately for any newly added unguarded loader.
#   ADVISORY -- loader has no [[ -v ]] guard but is listed in the
#            baseline (pre-existing debt, tracked until fixed).
#   STALE -- a baselined loader has since acquired a guard or been
#            removed; prune the baseline entry.
#   FAIL  -- zero loaders found (gate malfunction sentinel).
#
# The baseline (baseline-associative-dup-guard.baseline) lists script
# basenames of known-unguarded loaders.  It should shrink over time as
# guards are added; it must never grow without a documented reason.

set -u

NAME="baseline-associative-dup-guard"
ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CHECK_DIR="$ROOT/scripts/check-static"
SELF="baseline-associative-dup-guard.sh"
BASELINE="$CHECK_DIR/${NAME}.baseline"

fail() { echo "FAIL: $NAME: $*"; exit 1; }
pass() { echo "PASS: $NAME: $*"; exit 0; }

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

# ---------------------------------------------------------------------------
# Load baseline (script basenames exempt from the strict guard requirement).
# ---------------------------------------------------------------------------

declare -A _baselined
if [ -f "$BASELINE" ]; then
	while IFS= read -r bline; do
		[[ -z "$bline" || "$bline" == \#* ]] && continue
		if [[ -v _baselined["$bline"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $bline" >&2
			exit 1
		fi
		_baselined["$bline"]=1
	done < "$BASELINE"
fi

# ---------------------------------------------------------------------------
# Enumerate loaders: *.sh in CHECK_DIR with both declare -A and while-read.
# ---------------------------------------------------------------------------

loaders=()
for script in "$CHECK_DIR"/*.sh; do
	[ -f "$script" ] || continue
	bn=$(basename "$script")
	[ "$bn" = "$SELF" ] && continue
	# lib.sh is a shared helper, not a gate; exclude from loader population.
	[ "$bn" = "lib.sh" ] && continue
	grep -q 'declare -A' "$script" || continue
	grep -q 'while IFS= read' "$script" || continue
	loaders+=("$bn")
done

# Fail-close: zero loaders means something is structurally wrong.
if [ "${#loaders[@]}" -eq 0 ]; then
	fail "no declare -A + while-read baseline loaders found in $CHECK_DIR -- gate malfunction"
fi

# ---------------------------------------------------------------------------
# Check each loader for a [[ -v ]] dup guard.
# ---------------------------------------------------------------------------

unguarded_new=()
unguarded_advisory=()
declare -A _seen_in_loaders

for bn in "${loaders[@]}"; do
	_seen_in_loaders["$bn"]=1
	if grep -v '^[[:space:]]*#' "$CHECK_DIR/$bn" | grep -q '\[\[ -v '; then
		continue
	fi
	if [[ -v _baselined["$bn"] ]]; then
		unguarded_advisory+=("$bn")
	else
		unguarded_new+=("$bn")
	fi
done

# ---------------------------------------------------------------------------
# Stale baseline: entries for scripts that now have a guard or are gone.
# ---------------------------------------------------------------------------

stale=()
for key in "${!_baselined[@]}"; do
	if [[ ! -v _seen_in_loaders["$key"] ]]; then
		# Script no longer exists or is no longer classified as a loader.
		stale+=("$key")
	elif grep -v '^[[:space:]]*#' "$CHECK_DIR/$key" | grep -q '\[\[ -v '; then
		# Script has since acquired a [[ -v ]] guard; prune the baseline.
		stale+=("$key")
	fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#stale[@]} baseline entry/entries are now clean or no longer loaders."
		echo "  Remove the corresponding line(s) from:"
		echo "    scripts/check-static/${NAME}.baseline"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
	fail "${#stale[@]} stale baseline entry/entries"
fi

if [ "${#unguarded_new[@]}" -gt 0 ]; then
	{
		echo "  $NAME: ${#unguarded_new[@]} loader(s) load a declare -A from a baseline"
		echo "  via while IFS= read but have no [[ -v ]] dup guard before the insert:"
		for e in "${unguarded_new[@]}"; do echo "    $e"; done
		echo ""
		echo "  Duplicate baseline keys silently overwrite.  Guard each insert:"
		echo "    if [[ -v array[\"\$key\"] ]]; then"
		echo "      echo \"FAIL: \$NAME: duplicate baseline entry: \$key\" >&2"
		echo "      exit 1"
		echo "    fi"
		echo "    array[\"\$key\"]=\"\$value\""
		echo ""
		echo "  If this is intentional, add the script basename to:"
		echo "    scripts/check-static/${NAME}.baseline"
	} >&2
	fail "${#unguarded_new[@]} loader(s) without [[ -v ]] dup guard (${#unguarded_advisory[@]} pre-existing baselined)"
fi

total="${#loaders[@]}"
advisory="${#unguarded_advisory[@]}"
guarded=$(( total - advisory ))
pass "${total} loader(s) checked: ${guarded} guarded, ${advisory} pre-existing unguarded (baselined)"
