/*
 * SYSCALL_DEFINE1(pipe, int __user *, fildes)
 */
#include <unistd.h>
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

struct syscallentry syscall_pipe = {
	.name = "pipe",
	.num_args = 1,
	.arg1name = "fildes",
	.arg1type = ARG_ADDRESS,
	.group = GROUP_VFS,
};

/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

static unsigned long pipe2_flags[] = {
	O_CLOEXEC, O_NONBLOCK, O_DIRECT,
};

struct syscallentry syscall_pipe2 = {
	.name = "pipe2",
	.num_args = 2,
	.arg1name = "fildes",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(pipe2_flags),
	.group = GROUP_VFS,
};
