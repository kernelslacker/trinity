#!/bin/bash
#
# child-exit-zero-error-path: flag _exit(0) reachable from a child-side
# failure/abort path.
#
# Background: the fork-storm fast-die circuit breaker uses the child's
# exit status as the signal that it tripped a fatal condition.  A child
# that bails on an error path with _exit(0) is invisible to
# reap_entry_is_fast_die() and contributes nothing -- the breaker stays
# inert and the bug class silently degrades coverage instead of being
# noticed.  The kcov recovery-exhausted branch (commit e9a9ae95a4b1)
# was exactly this shape: a recovery-failure code path that quietly
# _exit(0)'d instead of returning a sentinel non-zero status.
#
# The check is a regex tripwire.  For every _exit(0) callsite in
# child-context source (childops/*.c, syscalls/*.c, child.c, kcov/kcov.c)
# it scans the preceding ~10 source lines in the same file for any of:
#
#   perror | outputerr | output_err | warn( | warnx | fprintf(stderr
#   fatal  | abort(    | goto err*  | goto fail*
#   case <label containing err|fail|abort|recovery_exhausted>
#
# A match means the _exit(0) is plausibly reachable from a failure
# branch.  The heuristic is deliberately simple and prone to false
# positives; happy-path _exit(0)s that the heuristic flags can be
# pinned in child-exit-zero-error-path.baseline.
#
# A bare happy-path _exit(0) at the bottom of a clean child task is
# legal and not flagged (no preceding error tokens).  Only callsites
# whose surrounding context smells like a failure branch are reported.

set -u

NAME="child-exit-zero-error-path"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/child-exit-zero-error-path.baseline"

# Load grandfathered file:lineno keys from the baseline.  Each line is
# `path/to/file.c:lineno  reason text...`; everything after the first
# whitespace block is treated as commentary.
declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		# Strip leading whitespace, then take field 1 (file:lineno).
		entry="${entry#"${entry%%[![:space:]]*}"}"
		key="${entry%%[[:space:]]*}"
		[ -z "$key" ] && continue
		BASELINED["$key"]=1
	done < "$BASELINE"
fi

# Token list scanned in the ~10-line lookback window.  Kept verbose for
# readability; the alternation is fed to grep -E.
TOKENS='perror|outputerr|output_err|warn\(|warnx|fprintf\(stderr|fatal|abort\(|goto[[:space:]]+err|goto[[:space:]]+fail'
CASE_TOKENS='^[[:space:]]*case[[:space:]].*(err|fail|abort|recovery_exhausted)'

# Build the file list explicitly so the check stays deterministic.
files=()
for d in "$ROOT/childops" "$ROOT/syscalls"; do
	[ -d "$d" ] || continue
	while IFS= read -r f; do
		files+=("$f")
	done < <(find "$d" -name '*.c' -type f | sort)
done
for f in "$ROOT/child.c" "$ROOT/kcov/kcov.c"; do
	[ -f "$f" ] && files+=("$f")
done

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

total_callsites=0
flagged=0

for srcfile in "${files[@]}"; do
	# Collect every `_exit(0)` line number in this file.  Match form
	# `_exit ( 0 )` with optional whitespace; reject _exit(<anything
	# else>) including _exit(KCOV_RECOVERY_EXHAUSTED_EXIT_CODE).
	while IFS=: read -r lineno content; do
		[ -z "$lineno" ] && continue

		# Skip the match if the _exit(0) appears inside a line
		# that is itself a comment.  Block-comment continuations
		# (`^\s*\*`), banner openers (`^\s*/\*`), and `//` line
		# comments cover the false positives the tree has today.
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac

		total_callsites=$((total_callsites + 1))

		# Read up to 10 lines preceding the callsite in the same
		# file.  Stay within the file -- crossing a function
		# boundary backwards is fine for a false-positive-friendly
		# heuristic; the baseline absorbs the noise.
		start=$((lineno - 10))
		[ "$start" -lt 1 ] && start=1
		end=$((lineno - 1))
		[ "$end" -lt "$start" ] && continue

		before="$(sed -n "${start},${end}p" "$srcfile")"

		matched=""
		if printf '%s\n' "$before" | grep -qE "$TOKENS"; then
			matched="$(printf '%s\n' "$before" | grep -oE "$TOKENS" | head -n 1)"
		elif printf '%s\n' "$before" | grep -qE "$CASE_TOKENS"; then
			matched="$(printf '%s\n' "$before" | grep -E "$CASE_TOKENS" | head -n 1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]\+/ /g')"
		fi

		[ -z "$matched" ] && continue

		relpath="${srcfile#"$ROOT"/}"
		key="$relpath:$lineno"
		if [ -n "${BASELINED[$key]+x}" ]; then
			# Pinned as a known-OK happy-path callsite that the
			# heuristic over-fires on.  Mark it consumed so the
			# baseline-staleness check below sees it.
			BASELINED["$key"]=2
			continue
		fi
		echo "$key: _exit(0) reachable from error path (matched: $matched)" >> "$hits_tmp"
		flagged=$((flagged + 1))
	done < <(grep -n -E '_exit[[:space:]]*\([[:space:]]*0[[:space:]]*\)' "$srcfile" 2>/dev/null)
done

# Stale baseline entries: pinned a callsite that no longer matches the
# heuristic (file moved, line shifted, exit was deleted, or the bug was
# fixed).  Non-fatal advisory -- surface on stderr but do not fail.
stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

if [ "$flagged" -gt 0 ]; then
	{
		echo "  $NAME: $flagged _exit(0) callsite(s) in child code reachable from an error path:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: change _exit(0) -> _exit(<sentinel>) so reap_entry_is_fast_die()"
		echo "       can see the failure, OR (only if the callsite is genuinely happy-path"
		echo "       and the heuristic is over-firing) pin it in"
		echo "       scripts/check-static/child-exit-zero-error-path.baseline with a reason."
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer match (consider pruning):"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "$flagged" -gt 0 ]; then
	echo "FAIL: $NAME: $flagged error-path _exit(0) callsite(s) in child code"
	exit 1
fi

baseline_size=${#BASELINED[@]}
echo "PASS: $NAME (callsites=$total_callsites, baselined=$baseline_size)"
exit 0
