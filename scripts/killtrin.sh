#!/bin/sh

for i in $(pgrep -x trinity);
do
  kill -9 $i
done
