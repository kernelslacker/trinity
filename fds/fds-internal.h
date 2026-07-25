#pragma once

#include <stdbool.h>

#include "fd.h"

/*
 * Shared state between the fds/ carve-outs (registry, init, picker,
 * protected-fd, replenish, param parser).  Everything here was previously
 * a file-static in fds/fds.c and stays semantically per-process, but it
 * has to be visible across the split files.  The header is deliberately
 * fds-only — no other subsystem should include it.
 */

/*
 * Per-init failure-reason slot.  fds/fds-init.c resets these immediately
 * before calling provider->init(); on a false return it logs whichever
 * reason the provider stamped via fd_provider_init_fail().  A provider
 * that returns false without calling the helper leaves the slot at
 * FD_INIT_REASON_NONE and the dispatcher falls back to the bare
 * "Error during initialization of <name>" line.
 */
extern enum fd_init_reason last_init_reason;
extern int last_init_errno;
extern char last_init_detail[128];
