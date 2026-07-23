#pragma once

/*
 * Private cross-file declarations shared between the main/reap-*.c
 * translation units.  Not part of the public trinity API -- callers
 * outside the main/reap-*.c family go through include/main-internal.h.
 */

#include <sys/types.h>

#include "child-api.h"

/* main/reap.c -- reap-core helpers reused by watchdog / signal paths. */
void reap_child(struct childdata *child, int childno, bool child_dead);

/* main/reap-fastdie.c -- fork-die-respawn busy-loop detector. */
void record_reap(int childno, int childstatus);
