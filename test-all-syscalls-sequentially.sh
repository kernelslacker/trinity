#!/bin/bash
#
# This is a useful test to run occasionally, to see which syscalls are
# causing trinity to segfault.

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

while [ 1 ]
do
for syscall in $(../trinity -L | grep -v Trinity | grep -v syscalls: | grep -v AVOID | grep 64-bit | awk '{ print $4 }' | sort -u)
do
	MALLOC_CHECK_=2 ../trinity -q -c $syscall -N 99999 -D -l off -C 64
	echo
	echo
done
done
