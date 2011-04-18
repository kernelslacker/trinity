#!/bin/bash

if [ ! -d logs ]; then
  mkdir logs
fi

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

NR=$(../trinity -L | tail -n1 | awk '{ print $1}' | sed s/://)

echo Starting $NR fuzzers

for i in $(seq 0 $NR)
do
	../trinity --mode=random --logfile=../logs/trinity-rand-syscall-$i.log -i -p -c $i &
done
