#!/bin/bash
#
# This is a useful test to run occasionally, to see which syscalls are
# causing trinity to segfault.

set -uo pipefail

. scripts/paths.sh
. scripts/taint.sh

while true
do
for syscall in $("$TRINITY_PATH/trinity" -L | grep entrypoint | grep -v AVOID | awk '{ print $3 }' | sort -u)
do
	pushd "$TRINITY_TMP" > /dev/null || exit 1

	if [ ! -f "$TRINITY_PATH/trinity" ]; then
		echo lost!
		pwd
		exit 1
	fi

	MALLOC_CHECK_=2 "$TRINITY_PATH/trinity" -c "$syscall" -N 1000000 -C 64 -x execve -x execveat

	chmod 755 "$TRINITY_TMP"
	popd > /dev/null || exit 1

	check_tainted
	echo
	echo
done
check_tainted
done
