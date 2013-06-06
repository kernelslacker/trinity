#!/bin/bash
#
# This is an example of how to search for an interaction between
# two syscalls.   In the example below I was chasing an oops in
# sendmsg that only occurred after connect was called.
#

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
chmod 755 tmp
cd tmp

TAINT=$(cat /proc/sys/kernel/tainted)

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`

while [ 1 ];
do


for sc in $(../trinity -L | grep entrypoint | grep -v AVOID | awk '{ print $4 }' | sort -u)
do
  mkdir -p tmp.$i
  pushd tmp.$i

  if [ ! -f ../../trinity ]; then
    echo lost!
    pwd
    exit
  fi

  ../../trinity -q -l off -n -c sendmsg -c $sc -C32 -N 999999

  popd

  check_tainted

  chmod 755 ../tmp

done

done
