#!/bin/bash
#
# no-time-subtraction: reject duration arithmetic that subtracts time(NULL).
#
# A duration computed as  time(NULL) - start  goes negative (and wraps to
# an enormous value in an unsigned field) whenever NTP steps the wall clock
# backwards.  Trinity's runtime timing must use mono_ns() / CLOCK_MONOTONIC
# so that a clock step cannot corrupt a duration or trigger a spurious
# timeout.
#
# The check scans all .c / .h files for the patterns:
#
#   time(NULL) -       (time(NULL) as the minuend)
#   - time(NULL)       (time(NULL) as the subtrahend)
#
# Comment lines (* / // / /*) are stripped so the single existing comment
# in syscalls/timer/timer_settime.c that describes this hazard does not
# produce a false positive.
#
# Mirrors the shape of no-bare-waitpid.sh.

set -u

NAME="no-time-subtraction"
ROOT="${REPO_ROOT:-$(pwd)}"

# Matches either  time(NULL)<optional-space>-   or   -<optional-space>time(NULL)
PATTERN='time\(NULL\)[[:space:]]*-|-[[:space:]]*time\(NULL\)'

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

while IFS= read -r srcfile; do
	grep -E -H -n "$PATTERN" "$srcfile" 2>/dev/null
done < <(find . \( -name '*.c' -o -name '*.h' \) -type f \
		-not -path './.git/*' -print | sort) | \
while IFS= read -r match; do
	# match is "path:lineno:content".  Split carefully so a colon
	# inside the source line does not corrupt the content field.
	path="${match%%:*}"
	rest="${match#*:}"
	lineno="${rest%%:*}"
	content="${rest#*:}"

	# Trim leading whitespace.
	trimmed="${content#"${content%%[![:space:]]*}"}"

	# Skip block-comment continuation, a banner opening with /*,
	# or a // line comment.
	case "$trimmed" in
		\**)   continue ;;
		/\**)  continue ;;
		//*)   continue ;;
	esac

	echo "${path#./}:$lineno: $trimmed"
done > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: time(NULL) subtraction found -- use mono_ns() instead"
		echo "  A wall-clock duration goes negative when NTP steps backwards."
		echo "  Offending site(s):"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: replace time(NULL) arithmetic with mono_ns() / CLOCK_MONOTONIC"
		echo "       so NTP backward steps cannot corrupt a duration."
	} >&2
	echo "FAIL: $NAME: $n time(NULL)-subtraction site(s)"
	exit 1
fi

echo "PASS: $NAME: 0 time(NULL)-subtraction sites"
exit 0
