#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

../scrashme --mode=rotate --logfile=../scrashme-cpu0.log -z -i
../scrashme --mode=rotate --logfile=../scrashme-cpu0.log -k -i
../scrashme --mode=rotate --logfile=../scrashme-cpu0.log -u -i

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

for i in `seq 0 $NR_CPUS`
do
	taskset -c $i ../scrashme --mode=random --logfile=../scrashme-cpu$i.log -i &
done
