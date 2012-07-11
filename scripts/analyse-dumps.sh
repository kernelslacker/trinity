#!/bin/sh

for core in $(find . -name "core.*")
do
  gdb -batch -n -ex 'bt' ./trinity $core > core.txt
  SHA=$(cat core.txt|  grep -v New\ LWP | sha1sum)
  cat core.txt > core-$SHA.txt
  rm -f core.txt
done

