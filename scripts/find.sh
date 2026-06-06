#!/bin/bash
#
# This is an example of how to search for an interaction between
# two syscalls.   In the example below I was chasing an oops involving
# ftruncate and another unknown syscall.
#
# I wanted to avoid execve, and the sync syscalls because they just slowed
# things down, and had already been ruled out.
#

set -uo pipefail

. scripts/paths.sh
. scripts/taint.sh

chmod 755 "$TRINITY_TMP"
cd "$TRINITY_TMP" || exit 1

while true;
do
  workdir=$(mktemp -d tmp.XXXXXX) || exit 1
  pushd "$workdir" >/dev/null || exit 1

  if [ ! -f "$TRINITY_PATH/trinity" ]; then
    echo lost!
    pwd
    exit 1
  fi

  "$TRINITY_PATH/trinity" -a64 -c ftruncate -r20 -x execve -x execveat -x syncfs -x sync -x fsync -x fdatasync -C64 -N 1000000 --enable-fds=pseudo,testfile

  popd >/dev/null || exit 1

  check_tainted

  chmod 755 "$TRINITY_TMP"

done
