#!/bin/bash

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

cd $TRINITY_TMP

NR_CPUS=$(nproc)
NR_PROCESSES=$(($NR_CPUS * 16))

while [ 1 ];
do
  rm -f trinity
  cp $TRINITY_PATH/trinity .
  chmod -w trinity

  if [ -d tmp ]; then
    chmod 755 tmp
    rm -rf tmp
  fi
  mkdir -p tmp

  pushd tmp > /dev/null

  rm -f trinity.socketcache

  MALLOC_CHECK_=2 ../trinity -q -l off -C $NR_PROCESSES $DROPPRIVS -N 1000000 -E SMC -a64

  chmod 755 $TRINITY_TMP
  popd > /dev/null

  check_tainted

done
