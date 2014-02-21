#!/bin/bash

OLDPATH=$(pwd)
TRINITY_PATH=${TRINITY_PATH:-$OLDPATH}

if [ -d tmp ]; then
  TRINITY_TMP=$(mktemp -d $(pwd)/tmp/trinity.XXXXXX)
else
  TRINITY_TMP=$(mktemp -d /tmp/trinity.XXXXXX)
fi

if [ $(/usr/bin/id -u) -eq 0 ] ; then
  DROPPRIVS=--dropprivs
else
  DROPPRIVS=""
fi

check_tainted()
{
    if [ "$(cat /proc/sys/kernel/tainted)" != $TAINT ]; then
      echo ERROR: Taint flag changed $(cat /proc/sys/kernel/tainted)
      exit
    fi
}

chmod 755 $TRINITY_TMP
cd $TRINITY_TMP

TAINT=$(cat /proc/sys/kernel/tainted)

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_PROCESSES=$(($NR_CPUS * 2))

while [ 1 ];
do
  rm -f trinity
  cp $TRINITY_PATH/trinity .
  chmod -w trinity

  for i in `seq 1 $NR_PROCESSES`
  do
    chmod 755 $TRINITY_TMP
    if [ -d tmp.$i ]; then
      chmod 755 tmp.$i
      rm -rf tmp.$i
    fi
    mkdir -p tmp.$i
    pushd tmp.$i > /dev/null

    if [ ! -f $TRINITY_PATH/trinity ]; then
      echo lost!
      pwd
      exit
    fi

    rm -f trinity.socketcache
    MALLOC_CHECK_=2 ../trinity -q -l off -N 999999 $DROPPRIVS &

    popd > /dev/null

    check_tainted
  done

  wait
  sleep 1
  check_tainted

  chmod 755 $TRINITY_TMP

  for i in `seq 1 $NR_PROCESSES`
  do
    rm -rf tmp.$i
  done

done
