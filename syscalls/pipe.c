/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "sanitise.h"
#include "deferred-free.h"

static void sanitise_pipe(struct syscallrecord *rec)
{
	rec->a1 = (unsigned long) malloc(sizeof(int) * 2);
}

static void post_pipe(struct syscallrecord *rec)
{
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
