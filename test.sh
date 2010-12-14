#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

../scrashme --mode=rotate -z
../scrashme --mode=rotate -k
../scrashme --mode=rotate -u
../scrashme --mode=rotate -z -i
../scrashme --mode=rotate -k -i
../scrashme --mode=rotate -u -i

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS+1))

for i in `seq 1 $NR_CPUS`
do
	../scrashme --mode=random &
	../scrashme --mode=random -i &
done
