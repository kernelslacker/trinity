#!/bin/bash

if [ ! -d logs ]; then
  mkdir logs
fi

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

while [ 1 ];
do
  for i in `seq 0 $NR_CPUS`
  do
	taskset -c $i ../trinity --mode=random --logfile=../logs/trinity-rand-cpu$i.log    -i -N 100 -F
	taskset -c $i ../trinity --mode=random --logfile=../logs/trinity-rand-cpu$i-32.log -i -N 100 -F --32bit
	rm -f trinity.socketcache
  done
done
