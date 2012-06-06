/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

#include <unistd.h>
#include <fcntl.h>

#include "trinity.h"
#include "sanitise.h"
#include "compat.h"

struct syscall syscall_pipe2 = {
	.name = "pipe2",
	.num_args = 2,
	.arg1name = "fildes",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 2,
		.values = { O_CLOEXEC, O_NONBLOCK, O_DIRECT },
	},
};
