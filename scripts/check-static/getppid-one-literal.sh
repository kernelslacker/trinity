#!/bin/bash
#
# getppid-one-literal: flag source lines that compare getppid() against the
# literal constant 1 to detect orphaning.
#
# Background
# ----------
# `if (getppid() == 1)` is only correct when the system's reaper for
# orphaned processes is PID 1 (init).  If any ancestor process has called
# prctl(PR_SET_CHILD_SUBREAPER, 1) -- systemd --user, a container init,
# or a libfuzzer/AFL harness -- orphaned children reparent to that ancestor
# instead of init.  The == 1 test then silently becomes dead code and the
# orphan-containment guarantee evaporates.
#
# The correct idiom captures the parent PID before arming PDEATHSIG:
#
#   pid_t saved_ppid = getppid();          /* before fork or as first child act */
#   (void)prctl(PR_SET_PDEATHSIG, SIGKILL);
#   if (getppid() != saved_ppid)           /* subreaper-safe orphan check */
#       _exit(0);
#
# This check scans .c files under the source tree for the getppid()==1
# literal pattern (both libc and raw-syscall forms) on non-comment lines,
# and reports any hit not pinned in the baseline as FAIL.
#
# 551c2d57bf5e ("userns-bootstrap: add getppid()==1 re-check after
# PR_SET_PDEATHSIG") introduced the last site converted in the batch that
# added this gate; those sites are now all fixed.  Any new occurrence must
# fail this check rather than being silently accepted.
#
# False-positive-friendly: sites that cannot be converted (e.g., because
# they genuinely test for PID 1 as a process identity, not as an orphan
# sentinel) can be pinned in getppid-one-literal.baseline with a reason.

set -u

NAME="getppid-one-literal"
ROOT="${REPO_ROOT:-$(pwd)}"
BASELINE="$ROOT/scripts/check-static/getppid-one-literal.baseline"

# Pattern: getppid() == 1 (with optional spaces around ==) in either the
# libc call form or the raw __NR_getppid syscall form.
PATTERN='(getppid[[:space:]]*\(\)|trinity_raw_syscall\([^)]*__NR_getppid[^)]*\)|syscall\([^)]*__NR_getppid[^)]*\))[[:space:]]*==[[:space:]]*1([^0-9]|$)'

# Load baselined file:lineno keys.
# Format: `path/to/file.c:lineno  reason text`
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
total=0

# Scan all .c files under the repository root.
while IFS= read -r srcfile; do
	while IFS=: read -r lineno content; do
		[ -z "$lineno" ] && continue

		# Skip lines that are comments (leading *, //, or /*).
		trimmed="${content#"${content%%[![:space:]]*}"}"
		case "$trimmed" in
			\**|/\**|//*) continue ;;
		esac

		total=$((total + 1))
		relpath="${srcfile#"$ROOT"/}"
		key="$relpath:$lineno"

		if [ -n "${BASELINED[$key]+x}" ]; then
			BASELINED["$key"]=2
			continue
		fi

		echo "$key: getppid()==1 literal (use saved-ppid idiom for subreaper safety)" >> "$hits_tmp"
		flagged=$((flagged + 1))
	done < <(grep -nE "$PATTERN" "$srcfile" 2>/dev/null)
done < <(find "$ROOT" -name '*.c' -type f \
	! -path '*/scripts/*' \
	| sort)

# Report stale baseline entries (advisory, non-fatal).
stale=()
for key in "${!BASELINED[@]}"; do
	if [ "${BASELINED[$key]}" = "1" ]; then
		stale+=("$key")
	fi
done

if [ "$flagged" -gt 0 ]; then
	{
		echo "  $NAME: $flagged getppid()==1 literal(s) found on non-comment lines:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: capture 'pid_t saved_ppid = getppid();' before prctl(PR_SET_PDEATHSIG)"
		echo "       and replace 'getppid() == 1' with 'getppid() != saved_ppid'."
		echo "       This is correct regardless of PR_SET_CHILD_SUBREAPER configuration."
		echo "       If the site genuinely tests for init as a process identity (not an"
		echo "       orphan sentinel), pin it in scripts/check-static/getppid-one-literal.baseline."
	} >&2
fi

if [ "${#stale[@]}" -gt 0 ]; then
	{
		echo "  note: ${#stale[@]} baseline entry/entries no longer match (consider pruning):"
		for e in "${stale[@]}"; do echo "    $e"; done
	} >&2
fi

if [ "$flagged" -gt 0 ]; then
	echo "FAIL: $NAME: $flagged getppid()==1 literal(s) not in baseline"
	exit 1
fi

baseline_size=${#BASELINED[@]}
echo "PASS: $NAME (hits=$total, baselined=$baseline_size)"
exit 0
