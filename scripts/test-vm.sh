#!/bin/bash
#
# This script demonstrates hunting for a VM bug that involved mmap + some other
# VM related syscall.

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

chmod 755 $TRINITY_TMP
cd $TRINITY_TMP

while [ 1 ];
do
  for syscall in madvise mbind migrate_pages mincore mlockall mlock move_pages mprotect mremap msync munlockall munlock munmap remap_file_pages vmsplice
  do
	echo testing mmap + $syscall
	pushd $TRINITY_TMP > /dev/null

	if [ ! -f $TRINITY_PATH/trinity ]; then
		echo lost!
		pwd
		exit
	fi

	MALLOC_CHECK_=2 $TRINITY_PATH/trinity -q -l off -c mmap -c $syscall -N 1000000 -C 64 $DROPPRIVS

	chmod 755 $TRINITY_TMP
	popd > /dev/null

	check_tainted
	echo
	echo
  done
  check_tainted
done
