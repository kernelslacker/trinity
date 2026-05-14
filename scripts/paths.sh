#!/bin/sh

TRINITY_PATH=${TRINITY_PATH:-$(pwd)}

if [ -d tmp ]; then
  TRINITY_TMP=$(mktemp -d "$(pwd)/tmp/trinity.XXXXXX")
else
  TRINITY_TMP=$(mktemp -d /tmp/trinity.XXXXXX)
fi
