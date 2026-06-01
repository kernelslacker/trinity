#pragma once

#include <stddef.h>

struct syscallrecord;

/*
 * Post-handler shape shared by shmget/msgget/semget.  On the ordinary
 * failure path (ret < 0, e.g. EEXIST / ENOSPC / EACCES with errno set)
 * the helper returns silently.  Otherwise it validates that retval fits
 * in 0..INT_MAX -- a value outside that range is the footprint of a
 * wild write into the syscallrecord retval slot (or a torn read of a
 * concurrent update), and silently truncating to (int) would feed
 * register_fn a fabricated id that the per-pool destructor would later
 * IPC_RMID against an unrelated object on the host.  On out-of-range
 * retval the helper logs through the @name-tagged oracle line and
 * bumps the corrupt-ptr counter.  On a valid id it calls
 * @register_fn((int)id) to publish the id into the per-child OBJ_LOCAL
 * pool for the matching type.
 */
void post_ipc_get(struct syscallrecord *rec,
		  void (*register_fn)(int id),
		  const char *name);
