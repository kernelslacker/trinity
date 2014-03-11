#!/bin/bash

OLDPATH=$(pwd)
TRINITY_PATH=${TRINITY_PATH:-$OLDPATH}

if [ -d tmp ]; then
  TRINITY_TMP=$(mktemp -d $(pwd)/tmp/trinity.XXXXXX)
else
  TRINITY_TMP=$(mktemp -d /tmp/trinity.XXXXXX)
fi

TRINITY_PATH=${TRINITY_PATH:-.}
TRINITY_TMP=$(mktemp -d /tmp/trinity.XXXXXX)

check_tainted()
{
    if [ "$(cat /proc/sys/kernel/tainted)" != $TAINT ]; then
      echo ERROR: Taint flag changed $(cat /proc/sys/kernel/tainted)
      exit
    fi
}

TAINT=$(cat /proc/sys/kernel/tainted)

chmod 755 $TRINITY_TMP
cd $TRINITY_TMP

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_PROCESSES=$(($NR_CPUS * 2))

while [ 1 ];
do
  for syscall in madvise mbind migrate_pages mincore mlockall mlock move_pages mprotect mremap msync munlockall munlock munmap remap_file_pages vmsplice
  do
	echo testing mmap + $syscall
	chmod 755 $TRINITY_TMP
	pushd $TRINITY_TMP > /dev/null

	if [ ! -f $TRINITY_PATH/trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 $TRINITY_PATH/trinity -q -l off -c mmap -c $syscall -N 99999 -C 64
	popd > /dev/null

	check_tainted
	echo
	echo
  done
  check_tainted
done
