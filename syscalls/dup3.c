/*
 * SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

#include <unistd.h>
#include <fcntl.h>

#include "trinity.h"
#include "sanitise.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC	02000000
#endif

struct syscall syscall_dup3 = {
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
	.retval = ARG_FD,
};
