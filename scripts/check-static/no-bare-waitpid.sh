#!/bin/bash
#
# no-bare-waitpid: reject bare waitpid() callsites outside the wrapper
# and the legitimate fuzz-target definitions.
#
# Trinity installs SIGALRM and SIGXCPU without SA_RESTART (health/signals.c),
# so any blocking waitpid() in a non-syscall path can return -1/EINTR.
# Treating EINTR as "done" leaves a child unreaped -- for sites that
# tear down a shared mapping right after the wait (barrier-racer,
# futex-storm) it also leaves a worker that will fault when it next
# touches the destroyed barrier.
#
# Every reap site routes through the EINTR-restartable waitpid_eintr()
# wrapper in include/utils.h instead.  Two locations are allowed to
# mention waitpid() at all:
#
#   include/utils.h      - the wrapper itself
#   syscalls/wait*.c     - the wait4 / waitpid / waitid syscall
#                          definitions, which fuzz the kernel's wait
#                          family and must call the bare syscall
#
# Everywhere else, bare waitpid() is forbidden.  This check grep-matches
# the token "waitpid" followed by `(` on a word boundary (so waitpid_eintr
# does not trigger) and then filters out comment lines (`/* ... */`,
# block-comment continuation `^\s*\*`, `//` line comments).  Anything
# that survives the filters fails the check.
#
# Mirrors the shape of no-libc-rand.sh.

set -u

NAME="no-bare-waitpid"
ROOT="${REPO_ROOT:-$(pwd)}"

# Word-boundary so waitpid_eintr is not matched.
PATTERN='\bwaitpid[[:space:]]*\('

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

# Walk every .c / .h file outside the allow-list and grep for the
# pattern.  Allow-list: include/utils.h (the wrapper) and
# syscalls/wait4.c / syscalls/waitpid.c / syscalls/waitid.c (the
# fuzz-target syscall definitions).
while IFS= read -r srcfile; do
	case "$srcfile" in
		./include/utils.h|include/utils.h)               continue ;;
		./syscalls/wait4.c|syscalls/wait4.c)             continue ;;
		./syscalls/waitpid.c|syscalls/waitpid.c)         continue ;;
		./syscalls/waitid.c|syscalls/waitid.c)           continue ;;
	esac

	grep -E -H -n "$PATTERN" "$srcfile" 2>/dev/null
done < <(find . \( -name '*.c' -o -name '*.h' \) -type f \
		-not -path './.git/*' -print | sort) | \
while IFS= read -r match; do
	# match is "path:line:content".  Split the first two colons off
	# manually so a colon inside the source line does not corrupt
	# the content field.
	path="${match%%:*}"
	rest="${match#*:}"
	lineno="${rest%%:*}"
	content="${rest#*:}"

	# Trim leading whitespace.
	trimmed="${content#"${content%%[![:space:]]*}"}"

	# Skip block-comment continuation, a banner that opens with
	# `/*`, or a `//` line comment.
	case "$trimmed" in
		\**)    continue ;;
		/\**)   continue ;;
		//*)    continue ;;
	esac

	echo "${path#./}:$lineno: $trimmed"
done > "$hits_tmp"

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: bare waitpid() callsite(s) outside the wrapper"
		echo "  and the wait-family syscall definitions:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: route through waitpid_eintr() from include/utils.h"
		echo "       so SIGALRM/SIGXCPU EINTR does not leave a child unreaped."
	} >&2
	echo "FAIL: $NAME: $n bare-waitpid callsite(s)"
	exit 1
fi

echo "PASS: $NAME: 0 bare-waitpid callsites outside the wrapper / wait*.c"
exit 0
