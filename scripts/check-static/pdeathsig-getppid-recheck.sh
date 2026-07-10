#!/bin/bash
#
# pdeathsig-getppid-recheck: flag PR_SET_PDEATHSIG callsites in child
# code that do not pair the prctl with a getppid()==1 re-check before
# the next blocking call.
#
# Background: a child that arms prctl(PR_SET_PDEATHSIG, SIGKILL, ...)
# and then immediately blocks on pause() / raw_futex_wait() / read()
# has a TOCTOU window: if the parent died between clone3() returning
# in the child and the prctl call landing, PDEATHSIG was set too late
# to ever fire.  The kernel reparents the child to PID 1 and it
# blocks forever -- a sibling leak that survives the whole fuzz run.
# The fix shape (see commit 53a4b05beea8 "childops/af-unix-scm-rights
# -gc: re-check getppid after PDEATHSIG") is a getppid()==1 test
# immediately after the prctl; if true, the parent is already gone
# and the child should _exit instead of blocking.
#
# The check is a regex tripwire.  For every PR_SET_PDEATHSIG arming
# callsite (the full `prctl(... PR_SET_PDEATHSIG ...)` or
# `syscall(__NR_prctl, PR_SET_PDEATHSIG, ...)` call -- bare mentions
# in comments are not flagged) in child-context source
# (childops/*.c, syscalls/*.c minus prctl.c, child.c) it scans the
# following ~30 source lines in the same file for one of:
#
#   getppid(    | syscall(__NR_getppid    | __NR_getppid
#
# A match means the recheck is present.  The lookahead window stops
# at the first line that looks like a function-body terminator
# (top-level `}` in column 0) so a recheck in a different function
# in the same file does not credit the wrong callsite.
#
# syscalls/prctl.c is excluded outright: that file is the syscall
# fuzzer for prctl itself, where PR_SET_PDEATHSIG is the *option
# being fuzzed* rather than a death-signal arming.  Cheapest
# exclusion; the surgical alternative would be to skip hits whose
# surrounding ~5 lines contain `case PR_SET_PDEATHSIG:`.
#
# False-positive-friendly: callsites that the heuristic over-fires
# on can be pinned in pdeathsig-getppid-recheck.baseline.

set -u

NAME="pdeathsig-getppid-recheck"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/pdeathsig-getppid-recheck.baseline"

# Load grandfathered file:lineno keys from the baseline.  Each line
# is `path/to/file.c:lineno  reason text...`; everything after the
# first whitespace block is treated as commentary.
declare -A BASELINED=()
if [ -r "$BASELINE" ]; then
	while IFS= read -r entry; do
		[ -z "$entry" ] && continue
		case "$entry" in \#*) continue ;; esac
		entry="${entry#"${entry%%[![:space:]]*}"}"
		key="${entry%%[[:space:]]*}"
		[ -z "$key" ] && continue
		BASELINED["$key"]=1
	done < "$BASELINE"
fi

# Tokens that constitute a getppid() re-check.  Both libc and raw
# syscall forms are accepted.
RECHECK_TOKENS='getppid[[:space:]]*\(|__NR_getppid'

# Lookahead window size in source lines.
LOOKAHEAD=30

# Build the file list explicitly so the check stays deterministic.
# syscalls/prctl.c is excluded -- see header.
files=()
if [ -d "$ROOT/childops" ]; then
	while IFS= read -r f; do
		files+=("$f")
	done < <(find "$ROOT/childops" -name '*.c' -type f | sort)
fi
if [ -d "$ROOT/syscalls" ]; then
	while IFS= read -r f; do
		[ "$f" = "$ROOT/syscalls/process/prctl.c" ] && continue
		files+=("$f")
	done < <(find "$ROOT/syscalls" -name '*.c' -type f | sort)
fi
[ -f "$ROOT/child.c" ] && files+=("$ROOT/child.c")

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

total_callsites=0
flagged=0

for srcfile in "${files[@]}"; do
	# Match the actual arming-call shape, not bare mentions:
	# either `prctl(... PR_SET_PDEATHSIG ...)` or
	# `syscall(__NR_prctl, PR_SET_PDEATHSIG, ...)`.  This keeps
	# comment lines like " * PR_SET_PDEATHSIG SIGKILL ..." out of
	# the callsite set.
	while IFS=: read -r lineno content; do
		[ -z "$lineno" ] && continue

		# Skip the match if the line is itself a comment.
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac

		total_callsites=$((total_callsites + 1))

		# Read up to LOOKAHEAD lines following the callsite.
		# Stop at a column-0 `}` (top-level closing brace) so a
		# recheck inside the next function in the same file
		# does not falsely credit this prctl.
		start=$((lineno + 1))
		end=$((lineno + LOOKAHEAD))

		window="$(sed -n "${start},${end}p" "$srcfile")"

		# Truncate the window at the first column-0 `}` -- that
		# terminates the enclosing function body.
		truncated="$(printf '%s\n' "$window" | awk '
			/^}/ { exit }
			{ print }
		')"

		if printf '%s\n' "$truncated" | grep -qE "$RECHECK_TOKENS"; then
			continue
		fi

		relpath="${srcfile#"$ROOT"/}"
		key="$relpath:$lineno"
		if [ -n "${BASELINED[$key]+x}" ]; then
			BASELINED["$key"]=2
			continue
		fi
		echo "$key: PR_SET_PDEATHSIG without getppid() re-check (recheck must follow within same function body)" >> "$hits_tmp"
		flagged=$((flagged + 1))
	done < <(grep -n -E '(prctl|__NR_prctl)[^A-Za-z0-9_].*PR_SET_PDEATHSIG' "$srcfile" 2>/dev/null)
done

# Stale baseline entries: pinned a callsite that no longer matches
# the heuristic.  Non-fatal advisory.
stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

if [ "$flagged" -gt 0 ]; then
	{
		echo "  $NAME: $flagged PR_SET_PDEATHSIG callsite(s) without a following getppid() re-check:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: add 'if (getppid() == 1) _exit(0);' (or the raw"
		echo "       syscall(__NR_getppid) equivalent) immediately after"
		echo "       the prctl, before the next blocking call.  See commit"
		echo "       53a4b05beea8 for the canonical fix shape.  If the"
		echo "       callsite is genuinely safe without a recheck, pin it"
		echo "       in scripts/check-static/pdeathsig-getppid-recheck.baseline"
		echo "       with a reason."
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer match (consider pruning):"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "$flagged" -gt 0 ]; then
	echo "FAIL: $NAME: $flagged unguarded PR_SET_PDEATHSIG callsite(s)"
	exit 1
fi

baseline_size=${#BASELINED[@]}
echo "PASS: $NAME (callsites=$total_callsites, baselined=$baseline_size)"
exit 0
