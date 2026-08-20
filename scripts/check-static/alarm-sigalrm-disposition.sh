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
# Emit $1 with C comments (block and line) removed, so a token that appears
# only inside a comment does not satisfy a content test.  Mirrors the
# comment-stripping the main scanner applies to its lookbehind window.
strip_c_comments() {
	awk '
		{
			line = $0; stripped = ""; i = 1; len = length(line)
			while (i <= len) {
				if (in_block) {
					if (substr(line, i, 2) == "*/") { in_block = 0; i += 2 }
					else { i++ }
				} else if (substr(line, i, 2) == "/*") {
					in_block = 1; i += 2
				} else if (substr(line, i, 2) == "//") {
					break
				} else {
					stripped = stripped substr(line, i, 1); i++
				}
			}
			print stripped
		}
	' "$1" 2>/dev/null
}

skipped_count=0

# Collect candidate files: .c files containing both alarm( and fork(.
# This is a file-level co-presence heuristic; per-function scoping is
# handled by the lookbehind window below.
while IFS= read -r srcfile; do
	relpath="${srcfile#"$ROOT"/}"

	# Path-based arm: childops/ and child/ files are fork-dispatched
	# children that will never carry the clone idiom the co-presence
	# heuristic requires.  Admit them unconditionally so a future real
	# alarm() callsite without a preceding signal(SIGALRM, SIG_DFL) reset
	# is caught rather than silently falling outside the gate.
	case "$relpath" in
		childops/*|child/*) : ;;
		*)
			# Must contain a process-creation call (the trigger for inherited dispositions).
			# Trinity childops clone via __NR_clone / __NR_fork as well as fork();
			# match any of the idioms so we don't miss raw-syscall sites.
			# Both tests run against comment-stripped content: a fork()
			# named only in a comment must not admit the file, and an
			# alarm() named only in a comment must not be counted as a
			# skipped (out-of-coverage) file.
			stripped_src="$(strip_c_comments "$srcfile")"
			if ! printf '%s\n' "$stripped_src" | grep -qE 'fork[[:space:]]*\(|vfork[[:space:]]*\(|clone[[:space:]]*\(|__NR_clone|__NR_fork|__NR_clone3'; then
				if printf '%s\n' "$stripped_src" | grep -qE '[^a-zA-Z_]alarm[[:space:]]*\(|^alarm[[:space:]]*\('; then
					skipped_count=$((skipped_count + 1))
				fi
				continue
			fi
			;;
	esac

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
			# Also strip comment lines so a reset mentioned only in a
			# comment does not falsely credit the site.
			window="$(printf '%s\n' "$window" | awk '
				/^}/ { in_block = 0; buf = ""; next }
				{
					line = $0
					stripped = ""
					i = 1
					len = length(line)
					while (i <= len) {
						if (in_block) {
							if (substr(line, i, 2) == "*/") { in_block = 0; i += 2 }
							else { i++ }
						} else if (substr(line, i, 2) == "/*") {
							in_block = 1; i += 2
						} else if (substr(line, i, 2) == "//") {
							break
						} else {
							stripped = stripped substr(line, i, 1); i++
						}
					}
					gsub(/^[[:space:]]+|[[:space:]]+$/, "", stripped)
					if (stripped == "") next
					buf = buf stripped "\n"
				}
				END { printf "%s", buf }
			')"
		fi

		# Check for the required reset in the truncated window.
		# Accept signal(SIGALRM, SIG_DFL) directly, or a sigaction(SIGALRM, ...)
		# call where the specific struct passed to sigaction(SIGALRM, &<id>, ...)
		# has .sa_handler = SIG_DFL assigned in the same window -- confirming
		# it resets the disposition rather than installing a handler.
		# Both checks must refer to the *same* struct identifier to prevent a
		# sibling-signal SIG_DFL assignment from satisfying the sigaction arm.
		if printf '%s\n' "$window" | \
		   grep -qE 'signal[[:space:]]*\([[:space:]]*SIGALRM[[:space:]]*,[[:space:]]*SIG_DFL'; then
			continue
		fi
		sigact_struct=$(printf '%s\n' "$window" | \
			grep -oE 'sigaction[[:space:]]*\([[:space:]]*SIGALRM[[:space:]]*,[[:space:]]*&([A-Za-z_][A-Za-z0-9_]*)' | \
			grep -oE '&[A-Za-z_][A-Za-z0-9_]*$' | tr -d '&')
		if [ -n "$sigact_struct" ] && printf '%s\n' "$window" | \
		   grep -qE "${sigact_struct}[.]sa_handler[[:space:]]*=[[:space:]]*SIG_DFL"; then
			continue
		fi

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
		echo "  fix: add 'signal(SIGALRM, SIG_DFL);' immediately before alarm(), or"
		echo "  use the sigaction(2) form: set '.sa_handler = SIG_DFL' on the SAME struct"
		echo "  passed to sigaction(SIGALRM, ...) -- e.g. 'sa.sa_handler = SIG_DFL; sigaction(SIGALRM, &sa, NULL);'."
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
echo "PASS: $NAME (callsites=$total_callsites, baselined=$baseline_size, skipped_files=$skipped_count)"
exit 0
