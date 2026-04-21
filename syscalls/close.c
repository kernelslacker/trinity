/*
 * SYSCALL_DEFINE1(close, unsigned int, fd)
 *
 * returns zero on success.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "child.h"
#include "fd-event.h"
#include "objects.h"
#include "pids.h"
#include "sanitise.h"

static void post_close(struct syscallrecord *rec)
{
	struct childdata *child;

	if (rec->retval != 0)
		return;

	/* Enqueue a CLOSE event so the parent can update the object pool.
	 * remove_object_by_fd() below bails in children (pid != mainpid),
	 * so the event queue is the actual path for child-initiated closes. */
	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL)
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
				 (int) rec->a1, -1, 0, 0, 0);

	/* Parent-side path (no-op in children). */
	remove_object_by_fd((int) rec->a1);
}

struct syscallentry syscall_close = {
	.name = "close",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fd" },
	.flags = AVOID_SYSCALL,
	.post = post_close,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
