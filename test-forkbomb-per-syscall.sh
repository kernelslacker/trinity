#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
chmod 755 tmp
cd tmp

NR=$(../trinity -L | tail -n1 | awk '{ print $1}' | sed s/://)

echo Starting $NR fuzzers

for i in $(seq 0 $NR)
do
	CPU=$(($RANDOM % $NR_CPUS))
	../trinity -q -c $i &
done
