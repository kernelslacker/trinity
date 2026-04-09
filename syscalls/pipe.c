/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "child.h"
#include "fd-event.h"
#include "objects.h"
#include "sanitise.h"
#include "deferred-free.h"

static void sanitise_pipe(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long) malloc(sizeof(int) * 2);
}

static void post_pipe(struct syscallrecord *rec)
{
	int *fds;
	struct childdata *child;

	if (rec->retval != 0)
		goto out;

	fds = (int *) rec->a1;
	if (fds == NULL)
		goto out;

	child = this_child();
	if (child != NULL && child->fd_event_ring != NULL) {
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CREATED,
				 fds[0], -1, OBJ_FD_PIPE);
		fd_event_enqueue(child->fd_event_ring, FD_EVENT_CREATED,
				 fds[1], -1, OBJ_FD_PIPE);
	}

out:
	deferred_freeptr(&rec->a1);
}

struct syscallentry syscall_pipe = {
	.name = "pipe",
	.num_args = 1,
	.argname = { [0] = "fildes" },
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe,
	.post = post_pipe,
};

/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

static unsigned long pipe2_flags[] = {
	O_CLOEXEC, O_NONBLOCK, O_DIRECT,
};

static void sanitise_pipe2(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long) malloc(sizeof(int) * 2);
}

struct syscallentry syscall_pipe2 = {
	.name = "pipe2",
	.num_args = 2,
	.argtype = { [1] = ARG_LIST },
	.argname = { [0] = "fildes", [1] = "flags" },
	.arg_params[1].list = ARGLIST(pipe2_flags),
	.group = GROUP_VFS,
	.sanitise = sanitise_pipe2,
	.post = post_pipe,
};
