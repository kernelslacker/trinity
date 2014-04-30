#!/bin/bash

. scripts/paths.sh

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

  chmod 755 $TRINITY_TMP
  if [ -d tmp ]; then
    chmod 755 tmp
    rm -rf tmp
  fi
  mkdir -p tmp
  pushd tmp > /dev/null

  rm -f trinity.socketcache

  MALLOC_CHECK_=2 ../trinity -q -l off -C $NR_PROCESSES $DROPPRIVS

  popd > /dev/null

  check_tainted

done
