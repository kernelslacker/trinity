#!/bin/sh

TRINITY_PATH=${TRINITY_PATH:-.}

# remove old cores
find . -name "core.*" -mtime +0 -delete

# Remove corrupted cores
find . -empty -name "core.*" -exec rm -f {} \;
for i in $(file core.* | grep -v $TRINITY_PATH/trinity | awk '{ print $1 }'  | sed 's/://'); do rm -f $i; done
