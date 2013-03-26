#!/bin/bash

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
NR_PROCESSES=$(($NR_CPUS * 2))

while [ 1 ];
do
  for i in `seq 1 $NR_PROCESSES`
  do
    mkdir -p tmp.$i
    pushd tmp.$i

    if [ ! -f ../../trinity ]; then
      echo lost!
      pwd
      exit
    fi

    MALLOC_CHECK_=2 ../../trinity -qq -l off &

    popd

    check_tainted
  done

  wait
  sleep 1
  check_tainted

  chmod 755 ../tmp

  for i in `seq 1 $NR_PROCESSES`
  do
    rm -rf tmp.$i
  done

done
