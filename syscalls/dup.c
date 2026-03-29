#include <unistd.h>
#include <fcntl.h>
#include "child.h"
#include "fd-event.h"
#include "objects.h"
#include "pids.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"

/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

/*
 * dup() creates a new fd pointing to the same file description.
 * Enqueue a DUP event so the parent can create a new object with
 * inherited type for the dup'd fd.
 */
static void post_dup(struct syscallrecord *rec)
{
	struct childdata *child;

	if ((long) rec->retval < 0)
		return;

	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL)
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_DUP,
				 (int) rec->a1, (int) rec->retval, 0);

	__atomic_add_fetch(&shm->fd_generation, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);
}

struct syscallentry syscall_dup = {
	.name = "dup",
	.num_args = 1,
	.argtype = { [0] = ARG_FD },
	.argname = { [0] = "fildes" },
	.rettype = RET_FD,
	.post = post_dup,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};

/*
 * dup2/dup3 silently close newfd if it was open, then dup oldfd to newfd.
 * Enqueue a CLOSE event for newfd (if it was tracked) and a DUP event
 * for the new oldfd→newfd mapping.
 */
static void post_dup2(struct syscallrecord *rec)
{
	struct childdata *child;

	if ((long) rec->retval < 0)
		return;

	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL) {
		/* newfd was implicitly closed */
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CLOSE,
				 (int) rec->a2, -1, 0);
		/* oldfd was duped to newfd */
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_DUP,
				 (int) rec->a1, (int) rec->retval, 0);
	}

	/* Parent-side path: remove_object_by_fd bails if not mainpid,
	 * so this is a no-op in children.  Keep for parent context. */
	remove_object_by_fd((int) rec->a2);
	__atomic_add_fetch(&shm->stats.fd_duped, 1, __ATOMIC_RELAXED);
}

/*
 * SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_dup2 = {
	.name = "dup2",
	.num_args = 2,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD },
	.argname = { [0] = "oldfd", [1] = "newfd" },
	.rettype = RET_FD,
	.post = post_dup2,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

static unsigned long dup3_flags[] = {
	O_CLOEXEC,
};

struct syscallentry syscall_dup3 = {
	.name = "dup3",
	.num_args = 3,
	.argtype = { [0] = ARG_FD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "oldfd", [1] = "newfd", [2] = "flags" },
	.arg3list = ARGLIST(dup3_flags),
	.rettype = RET_FD,
	.post = post_dup2,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
