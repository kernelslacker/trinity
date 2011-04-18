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

for i in `seq 0 $NR_CPUS`
do
	taskset -c $i ../trinity --mode=random --logfile=../logs/trinity-rand-cpu$i.log -i -F &
	taskset -c $i ../trinity --mode=random --logfile=../logs/trinity-rand-cpu$i-32.log -i --32bit -F &
done
