#!/bin/bash
#
# no-grep-c-or-echo: ban the $(grep -c ... || echo 0) idiom in scripts/.
#
# grep -c already prints 0 and exits 1 on zero matches.  The || echo 0 arm
# also fires on that exit-1, producing the two-line string "0\n0".  A
# numeric comparison like [ "$count" -ne N ] then aborts with "integer
# expression expected" and skips the guard entirely -- fail-open on the
# exactly the zero-count case the guard is meant to catch.
#
# The fix is to drop || echo 0 and let grep -c speak for itself.

set -u

NAME="no-grep-c-or-echo"
ROOT="${REPO_ROOT:-$(pwd)}"

cd "$ROOT" || { echo "FAIL: $NAME: cannot cd to $ROOT"; exit 1; }

hits_tmp="$(mktemp)"
trap 'rm -f "$hits_tmp"' EXIT

grep -rn --include='*.sh' -E '\$\(grep -c[^)]*\|\| *echo' scripts/ 2>/dev/null \
	| grep -v 'no-grep-c-or-echo\.sh' \
	> "$hits_tmp" || true

n="$(wc -l < "$hits_tmp" | tr -d ' ')"

if [ "$n" -gt 0 ]; then
	{
		echo "  $NAME: grep-c-or-echo idiom found in scripts/ -- fail-open on zero matches:"
		sed 's/^/    /' "$hits_tmp"
		echo "  fix: drop '|| echo 0'; grep -c already prints 0 on zero matches."
		echo "       The || arm fires on exit-1 too, yielding '0\\n0' which breaks"
		echo "       [ \"\$count\" -ne N ] with 'integer expression expected'."
	} >&2
	echo "FAIL: $NAME: $n grep-c-or-echo site(s) in scripts/"
	exit 1
fi

echo "PASS: $NAME: 0 grep-c-or-echo sites in scripts/"
exit 0
