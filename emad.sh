#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

for i in `seq 1 50`;
do
	../scrashme -r -t &
done
