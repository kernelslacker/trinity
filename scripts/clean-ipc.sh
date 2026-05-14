#!/bin/sh

for s in `ipcs -m | grep $(whoami) | awk '{ print $2 }'`; do   ipcrm -m $s; done

for s in `ipcs -q | grep $(whoami) | grep -v ^0x00000000 | awk '{ print $1 }'`
do
  ipcrm -Q $s
done


