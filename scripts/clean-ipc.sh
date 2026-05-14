#!/bin/sh

for s in $(ipcs -m | grep -w "$(whoami)" | awk '{ print $2 }'); do   ipcrm -m "$s"; done

for s in $(ipcs -q | grep -w "$(whoami)" | grep -v ^0x00000000 | awk '{ print $1 }')
do
  ipcrm -Q "$s"
done


