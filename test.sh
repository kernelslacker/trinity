#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

../trinity --mode=rotate --logfile=../trinity-cpu0.log -z -i
../trinity --mode=rotate --logfile=../trinity-cpu0.log -k -i
../trinity --mode=rotate --logfile=../trinity-cpu0.log -u -i

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

for i in `seq 0 $NR_CPUS`
do
	taskset -c $i ../trinity --mode=random --logfile=../trinity-cpu$i.log -i &
done
