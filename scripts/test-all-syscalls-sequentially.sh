#!/bin/bash
#
# This is a useful test to run occasionally, to see which syscalls are
# causing trinity to segfault.

check_tainted()
{
    if [ "$(cat /proc/sys/kernel/tainted)" != $TAINT ]; then
      echo ERROR: Taint flag changed $(cat /proc/sys/kernel/tainted)
      exit
    fi
}

if [ ! -d tmp ]; then
  mkdir tmp
fi

TAINT=$(cat /proc/sys/kernel/tainted)

while [ 1 ]
do
for syscall in $(./trinity -L | grep entrypoint | grep -v AVOID | awk '{ print $4 }' | sort -u)
do
	chmod 755 tmp
	pushd tmp

	if [ ! -f ../trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 ../trinity -q -c $syscall -N 99999 -l off -C 64
	popd

	check_tainted
	echo
	echo
done
check_tainted
done
