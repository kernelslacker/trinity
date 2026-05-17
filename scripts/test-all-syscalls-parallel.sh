#!/bin/bash

. scripts/paths.sh
. scripts/privs.sh
. scripts/taint.sh

chmod 755 $TRINITY_TMP
cd "$TRINITY_TMP" || exit 1

NR_CPUS=$(nproc)

while true;
do
  $TRINITY_PATH/trinity -L | grep entrypoint | grep -v AVOID | awk '{ print $3 }' | sort -u | \
    xargs -P "$NR_CPUS" -I{} env MALLOC_CHECK_=2 $TRINITY_PATH/trinity -c {} $DROPPRIVS
  check_tainted
done
