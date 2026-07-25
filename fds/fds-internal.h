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

/*
 * Provider registration list.  The list-head node is heap-allocated on
 * first register_fd_provider() call (which runs from REG_FD_PROV
 * constructors, before main()) and never freed.  num_fd_providers is the
 * count of entries linked into fd_providers->list.  Both are consumed by
 * every carve-out that walks the provider list — init dispatch, picker,
 * child_ops/replenish, param parser.
 */
extern struct fd_provider *fd_providers;
extern unsigned int num_fd_providers;

/*
 * Enable/disable accounting driven by the --enable-fds / --disable-fds
 * CLI parser and finalised by open_fds().  num_fd_providers_to_enable
 * counts request coming in from the parser; num_fd_providers_enabled and
 * num_fd_providers_initialized are written by the init dispatch and
 * consulted from the startup log line.
 */
extern unsigned int num_fd_providers_to_enable;
extern unsigned int num_fd_providers_enabled;
extern unsigned int num_fd_providers_initialized;

/*
 * Flat array of enabled+initialized providers, built once at the tail of
 * open_fds() from the registered fd_providers list, for O(1) random
 * selection by the picker.  num_active_providers is 0 before open_fds()
 * runs.
 */
extern struct fd_provider **active_providers;
extern unsigned int num_active_providers;
