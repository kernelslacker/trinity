#!/bin/bash

for _ in $(seq 1 10)
do
  prev=$(lsmod | wc -l)
  for j in $(lsmod | awk '{ print $1 }' | grep -v caif | grep -v Module)
  do
    modprobe -r "$j"
  done
  curr=$(lsmod | wc -l)
  if [ "$curr" -ge "$prev" ]; then
    break
  fi
done
