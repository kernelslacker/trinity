#!/bin/bash

if [ ! -d logs ]; then
  mkdir logs
fi

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

NR=$(../trinity -L | tail -n1 | awk '{ print $1}' | sed s/://)

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

echo Starting $NR fuzzers

for i in $(seq 0 $NR)
do
	CPU=$(($RANDOM % $NR_CPUS))
	taskset -c $CPU ../trinity --logfile=../logs/trinity-rand-syscall-$i.log -c $i &
done
