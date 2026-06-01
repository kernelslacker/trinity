/*
 * Post-handler helpers shared across the SysV IPC syscall family.
 *
 * The three direct *get post handlers (shmget, msgget, semget) each
 * open-coded the same shape: bound-check retval against 0..INT_MAX,
 * bump the corrupt-ptr counter on overflow, otherwise publish the id
 * into the per-child OBJ_LOCAL pool.  The bound-check is the anti-
 * wild-write guard documented in 23d92a7b27fa for the sysvipc
 * multiplexer; the per-direct-syscall sites had the same shape but
 * with cut-and-pasted oracle lines and register hooks.  Folding the
 * shape here lets each per-syscall .post body shrink to a trampoline.
 */
#include <limits.h>
#include "ipc-common.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

void post_ipc_get(struct syscallrecord *rec,
		  void (*register_fn)(int id),
		  const char *name)
{
	unsigned long retval = rec->retval;
	long ret = (long) retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	if (ret > INT_MAX) {
		output(0, "%s oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  name, retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	register_fn((int) ret);
}
