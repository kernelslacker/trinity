#!/bin/bash
#
# alarm-sigalrm-disposition: flag alarm() callsites in files that also
# contain fork() without a preceding signal(SIGALRM, SIG_DFL) reset in
# the same function body.
#
# Background: fork() without execve() gives the child a private copy of
# the parent's signal dispositions.  Trinity fuzz children install a
# SIGALRM flag-setter (health/signals-policy.c) so alarm() in any
# child reached by plain fork() merely sets a flag and returns rather
# than delivering a fatal signal.  The watchdog is silently dead.
#
# The fix shape (commit fdb73bc89fe4 ("userns-bootstrap: fix grandchild SIGALRM disposition and alarm clobber")) is:
#   signal(SIGALRM, SIG_DFL);
#   alarm(N);
#
# This check finds .c files that contain both alarm( and fork( (the
# co-presence heuristic for "could reach a fork child"), then for each
# alarm() callsite (excluding comment lines) verifies that
# signal(SIGALRM, SIG_DFL) appears within the preceding
# LOOKBEHIND source lines without crossing a function boundary (a
# top-level `}` at column 0).
#
# False positives (alarm() in parent scope with fork() elsewhere in the
# same file but no child-side watchdog issue) can be pinned in the
# baseline file below.

set -u

NAME="alarm-sigalrm-disposition"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/alarm-sigalrm-disposition.baseline"

# Lines to look back for the signal(SIGALRM, SIG_DFL) reset.
LOOKBEHIND=10

declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		entry="${entry#"${entry%%[![:space:]]*}"}"
		key="${entry%%[[:space:]]*}"
		[ -z "$key" ] && continue
		if [[ -v BASELINED["$key"] ]]; then
			echo "FAIL: $NAME: duplicate baseline entry: $key" >&2
			exit 1
		fi
		BASELINED["$key"]=1
	done < "$BASELINE"
fi

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

flagged=0
total_callsites=0

# Collect candidate files: .c files containing both alarm( and fork(.
# This is a file-level co-presence heuristic; per-function scoping is
# handled by the lookbehind window below.
while IFS= read -r srcfile; do
	# Must contain fork( (the trigger for inherited dispositions).
	grep -qE 'fork[[:space:]]*\(' "$srcfile" 2>/dev/null || continue

	# Scan each alarm() callsite in the file.
	while IFS=: read -r lineno content; do
		[ -z "$lineno" ] && continue

		# Skip comment lines.
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac

		total_callsites=$((total_callsites + 1))

		# Read up to LOOKBEHIND lines before the callsite, stopping at
		# the first column-0 `}` (top-level function-body terminator)
		# so a reset in a different function does not credit this site.
		start=$((lineno - LOOKBEHIND))
		[ "$start" -lt 1 ] && start=1
		end=$((lineno - 1))

		if [ "$end" -lt "$start" ]; then
			# alarm() is the very first line; no room for a reset.
			window=""
		else
			window="$(sed -n "${start},${end}p" "$srcfile")"
			# Truncate at the last column-0 `}` before the callsite
			# (i.e. keep only lines after the most recent function
			# boundary in the window).
			window="$(printf '%s\n' "$window" | awk '
				/^}/ { buf = "" ; next }
				{ buf = buf $0 "\n" }
				END { printf "%s", buf }
			')"
		fi

		# Check for the required reset in the truncated window.
		if printf '%s\n' "$window" | \
		   grep -qE 'signal[[:space:]]*\([[:space:]]*SIGALRM[[:space:]]*,[[:space:]]*SIG_DFL'; then
			continue
		fi

		relpath="${srcfile#"$ROOT"/}"
		key="$relpath:$lineno"
		if [ -n "${BASELINED[$key]+x}" ]; then
			BASELINED["$key"]=2
			continue
		fi

		echo "$key: alarm() without preceding signal(SIGALRM, SIG_DFL) in fork()-containing file" \
			>> "$hits_tmp"
		flagged=$((flagged + 1))
	done < <(grep -nE '[^a-zA-Z_]alarm[[:space:]]*\(|^alarm[[:space:]]*\(' "$srcfile" 2>/dev/null)
done < <(find "$ROOT" -name '*.c' -type f \
	-not -path "$ROOT/scripts/check-static/*" \
	| sort)

# Stale baseline advisory.
stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

if [ "$flagged" -gt 0 ]; then
	{
		echo "  $NAME: $flagged alarm() callsite(s) in fork()-containing files"
		echo "  without a preceding signal(SIGALRM, SIG_DFL) reset:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: add 'signal(SIGALRM, SIG_DFL);' immediately before alarm()."
		echo "  Background: fork() without execve() inherits the parent's SIGALRM"
		echo "  flag-setter, making alarm() a no-op watchdog.  See commit"
		echo '  fdb73bc89fe4 ("userns-bootstrap: fix grandchild SIGALRM disposition and alarm clobber")'
		echo "  If the site is genuinely safe (e.g. alarm() is in the parent scope"
		echo "  and never inherited), pin it in:"
		echo "    scripts/check-static/alarm-sigalrm-disposition.baseline"
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer match (consider pruning):"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "$flagged" -gt 0 ]; then
	echo "FAIL: $NAME: $flagged unguarded alarm() callsite(s)"
	exit 1
fi

baseline_size=${#BASELINED[@]}
echo "PASS: $NAME (callsites=$total_callsites, baselined=$baseline_size)"
exit 0
