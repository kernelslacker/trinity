/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_pipe(struct syscallrecord *rec)
{
	void *p = malloc(sizeof(int) * 2);

	rec->a1 = (unsigned long) p;
	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_pipe() runs. */
	rec->post_state = (unsigned long) p;
}

static void post_pipe(struct syscallrecord *rec)
{
	void *fildes = (void *) rec->post_state;

	if (fildes == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, fildes)) {
		outputerr("post_pipe: rejected suspicious fildes=%p (pid-scribbled?)\n", fildes);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a1 = 0;
	deferred_freeptr(&rec->post_state);
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

#ifndef O_NOTIFICATION_PIPE
#define O_NOTIFICATION_PIPE	O_EXCL
#endif

static unsigned long pipe2_flags[] = {
	O_CLOEXEC, O_NONBLOCK, O_DIRECT, O_NOTIFICATION_PIPE,
};

static void sanitise_pipe2(struct syscallrecord *rec)
{
	void *p = malloc(sizeof(int) * 2);

	rec->a1 = (unsigned long) p;
	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_pipe() runs. */
	rec->post_state = (unsigned long) p;
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
