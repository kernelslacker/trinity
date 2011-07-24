#!/bin/bash

if [ ! -d logs ]; then
  mkdir logs
fi

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

NR_CPUS=`grep ^processor /proc/cpuinfo | /usr/bin/wc -l`
NR_CPUS=$(($NR_CPUS-1))

while [ 1 ];
do
  RND=$RANDOM
  mkdir tmp.$RND
  cd tmp.$RND
  for i in `seq 0 $NR_CPUS`
  do
	taskset -c $i ../../trinity --mode=random --logfile=../../logs/trinity-rand-cpu$i.log    -i -N 1000 &
  done
  wait
  cd ..
  rm -rf tmp.$RND
done
