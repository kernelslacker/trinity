#!/bin/bash

if [ ! -d tmp ]; then
  mkdir tmp
fi
cd tmp

for i in `seq 1 10`
do
	../scrashme --mode=rotate -z &
	../scrashme --mode=rotate -k &
	../scrashme --mode=random &
	../scrashme --mode=random -i &
done
