#!/bin/bash

. scripts/paths.sh
. scripts/taint.sh

chmod 755 $TRINITY_TMP
cd "$TRINITY_TMP" || exit 1

NR_CPUS=$(nproc)

while true;
do
  $TRINITY_PATH/trinity -L | sort -u | \
    xargs -P "$NR_CPUS" -I{} env MALLOC_CHECK_=2 $TRINITY_PATH/trinity -c {}
  check_tainted
done
