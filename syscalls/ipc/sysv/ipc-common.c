/*
 * Post-handler helpers shared across the SysV IPC syscall family.
 *
 * Five direct *get / *ctl post handlers (shmget, msgget, semget,
 * shmctl, msgctl) each open-coded one of two shapes:
 *
 *   1. *get: bound-check retval against 0..INT_MAX, then publish the
 *      id into the per-child OBJ_LOCAL pool.  The bound check is the
 *      anti-wild-write guard documented in 23d92a7b27fa for the
 *      sysvipc multiplexer; the per-direct-syscall sites had the same
 *      shape with only the oracle prefix and the register hook
 *      differing.
 *
 *   2. *ctl: validate the pre-allocated out-buffer snap on
 *      rec->post_state via heap-shape + magic-cookie + ownership-table
 *      gates, then deferred-free the inner buf and the snap.  Both
 *      shmctl_post_state and msgctl_post_state carried identical
 *      fields and identical guard sequences with only the syscall
 *      name and the magic constant differing.
 *
 * Folding both shapes here lets each per-syscall .post body shrink to
 * a trampoline and lets the shmctl/msgctl sanitisers share one snap
 * shape and one allocation site.
 */
#include <limits.h>
#include <stddef.h>
#include "deferred-free.h"
#include "ipc-common.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

#define IPCCTL_POST_STATE_MAGIC	0x49504343544C5F4DUL	/* "IPCCTL_M" */

struct ipcctl_post_state {
	unsigned long magic;
	unsigned long buf;
	size_t buf_size;
};

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

void ipcctl_post_state_alloc(struct syscallrecord *rec,
			     void *buf, size_t buf_size)
{
	struct ipcctl_post_state *snap;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic    = IPCCTL_POST_STATE_MAGIC;
	snap->buf      = (unsigned long) buf;
	snap->buf_size = buf_size;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

void post_ipcctl_buf_free(struct syscallrecord *rec, const char *name)
{
	struct ipcctl_post_state *snap =
		(struct ipcctl_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("%s: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  name, snap);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as an
	 * ipcctl_post_state.  Bail without freeing on mismatch.
	 */
	if (snap->magic != IPCCTL_POST_STATE_MAGIC) {
		outputerr("%s: rejected snap with bad magic 0x%lx at %p "
			  "(post_state-stomped to foreign allocation?)\n",
			  name, snap->magic, snap);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * Shape + magic passed, but a foreign chunk could in principle
	 * carry the matching cookie by coincidence (e.g. another in-flight
	 * IPC ctl child's snap).  Verify against the ownership table so
	 * only snaps we registered at sanitise time can reach free().
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("%s: rejected post_state=%p (buf_size=%zu) "
			  "not in ownership table (post_state-redirected?)\n",
			  name, snap, snap->buf_size);
		rec->a3 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a3 = 0;
	deferred_freeptr(&snap->buf);
	post_state_unregister(snap);
	deferred_freeptr(&rec->post_state);
}
