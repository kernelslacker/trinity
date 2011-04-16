/*
 * SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
 */

#include <unistd.h>

{
	.name = "pipe2",
	.num_args = 2,
	.arg1name = "fildes",
	.arg1type = ARG_ADDRESS,
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 2,
		.values = { O_CLOEXEC , O_NONBLOCK },
	},
},
