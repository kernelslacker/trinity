#!/bin/bash
#
# This is a useful test to run occasionally, to see which syscalls are
# causing trinity to segfault.

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

while [ 1 ]
do
for syscall in $($TRINITY_PATH/trinity -L | grep entrypoint | grep -v AVOID | awk '{ print $3 }' | sort -u)
do
	pushd $TRINITY_TMP

	if [ ! -f $TRINITY_PATH/trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 $TRINITY_PATH/trinity -q -c $syscall -N 1000000 -l off -C 64 $DROPPRIVS -x execve

	chmod 755 $TRINITY_TMP
	popd

	check_tainted
	echo
	echo
done
check_tainted
done
