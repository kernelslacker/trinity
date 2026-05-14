#!/bin/sh
#
# Do a random subset of VM related syscalls.
# (Always do mmap, so the child processes have some local maps)

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

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

while true;
do
	syscalls="-c mmap"
	for _ in 1 2 3
	do
	  syscalls="$syscalls -c ${ARRAY[$((RANDOM % 15))]}"
	done

	echo testing $syscalls

	chmod 755 $TRINITY_TMP
	pushd $TRINITY_TMP > /dev/null

	if [ ! -f $TRINITY_PATH/trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 $TRINITY_PATH/trinity $syscalls -N 99999 -C 64
	popd > /dev/null

	check_tainted
	echo
	echo
done
