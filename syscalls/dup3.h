/*
 * SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
 */

#include <unistd.h>

{
	.name = "dup3",
	.num_args = 3,
	.arg1name = "oldfd",
	.arg1type = ARG_FD,
	.arg2name = "newfd",
	.arg2type = ARG_FD,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 1,
		.values = { O_CLOEXEC },
	},
},
