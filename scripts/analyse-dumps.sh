#!/bin/sh

TRINITY_PATH=${TRINITY_PATH:-.}

for core in tmp/trinity.*/tmp/core.*
do
  gdb -batch -n -ex 'bt' $TRINITY_PATH/trinity $core > core.txt
  SHA=$(cat core.txt| grep -v New\ LWP | grep -v childno | sha1sum | awk '{ print $1 }')
  cat core.txt > core-$SHA.txt
  rm -f core.txt
done

