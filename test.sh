#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

../trinity --mode=rotate --logfile=../trinity-z.log -z -i
../trinity --mode=rotate --logfile=../trinity-k.log -k -i
../trinity --mode=rotate --logfile=../trinity-u.log -u -i
../trinity --mode=rotate --logfile=../trinity-z32.log -z -i --32bit
../trinity --mode=rotate --logfile=../trinity-k32.log -k -i --32bit
../trinity --mode=rotate --logfile=../trinity-u32.log -u -i --32bit

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

for i in `seq 0 $NR_CPUS`
do
	taskset -c $i ../trinity --mode=random --logfile=../trinity-rand-cpu$i.log -i &
	taskset -c $i ../trinity --mode=random --logfile=../trinity-rand-cpu$i-32.log -i --32bit &
done
