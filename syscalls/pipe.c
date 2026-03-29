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
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "fildes" },
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
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LIST },
	.argname = { [0] = "fildes", [1] = "flags" },
	.arg_params[1].list = ARGLIST(pipe2_flags),
	.group = GROUP_VFS,
};
