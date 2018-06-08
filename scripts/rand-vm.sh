#!/bin/sh
#
# Do a random subset of VM related syscalls.
# (Always do mmap, so the child processes have some local maps)

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

ARRAY[0]="madvise"
ARRAY[1]="mbind"
ARRAY[2]="migrate_pages"
ARRAY[3]="mincore"
ARRAY[4]="mlockall"
ARRAY[5]="mlock"
ARRAY[6]="move_pages"
ARRAY[7]="mprotect"
ARRAY[8]="mremap"
ARRAY[9]="msync"
ARRAY[10]="munlockall"
ARRAY[11]="munlock"
ARRAY[12]="munmap"
ARRAY[13]="remap_file_pages"
ARRAY[14]="vmsplice"

while [ 1 ];
do
	syscalls="-c mmap"
	for i in $(seq 0 2)
	do
	  syscalls=$(echo $syscalls -c ${ARRAY[$(($RANDOM % 15))]})
	done

	echo testing $syscalls

	chmod 755 $TRINITY_TMP
	pushd $TRINITY_TMP > /dev/null

	if [ ! -f $TRINITY_PATH/trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 $TRINITY_PATH/trinity -q -l off $syscalls -N 99999 -C 64
	popd > /dev/null

	check_tainted
	echo
	echo
done
