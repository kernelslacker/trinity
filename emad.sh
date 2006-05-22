#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

for i in `seq 1 20`;
do
	../scrashme -z &
	../scrashme -r -t &
	../scrashme -r -t -i &
done
