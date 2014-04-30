#!/bin/sh

OLDPATH=$(pwd)
TRINITY_PATH=${TRINITY_PATH:-$OLDPATH}

if [ -d tmp ]; then
  TRINITY_TMP=$(mktemp -d $(pwd)/tmp/trinity.XXXXXX)
else
  TRINITY_TMP=$(mktemp -d /tmp/trinity.XXXXXX)
fi
