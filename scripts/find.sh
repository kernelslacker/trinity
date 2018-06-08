#!/bin/bash
#
# This is an example of how to search for an interaction between
# two syscalls.   In the example below I was chasing an oops involving
# ftruncate and another unknown syscall.
#
# I wanted to avoid execve, and the sync syscalls because they just slowed
# things down, and had already been ruled out.
#

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

chmod 755 $TRINITY_TMP
cd $TRINITY_TMP

NR_CPUS=$(nproc)

while [ 1 ];
do
  mkdir -p tmp.$i
  pushd tmp.$i

  if [ ! -f $TRINITY_PATH/trinity ]; then
    echo lost!
    pwd
    exit
  fi

  $TRINITY_PATH/trinity $DROPPRIVS -q -l off -a64 -c ftruncate -r20 -x execve -x execveat -x syncfs -x sync -x fsync -x fdatasync -C64 -N 1000000 --enable-fds=pseudo,testfile

  popd

  check_tainted

  chmod 755 $TRINITY_TMP

done
