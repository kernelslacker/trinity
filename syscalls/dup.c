#include <unistd.h>
#include <fcntl.h>
#include "sanitise.h"
#include "compat.h"

/*
 * SYSCALL_DEFINE1(dup, unsigned int, fildes)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_dup = {
	.name = "dup",
	.num_args = 1,
	.arg1name = "fildes",
	.arg1type = ARG_FD,
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};

/*
 * SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
 *
 * On success, returns the new descriptor.
 * On error, -1 is returned, and errno is set appropriately.
 */

struct syscallentry syscall_dup2 = {
	.name = "dup2",
	.num_args = 2,
	.arg1name = "oldfd",
	.arg1type = ARG_FD,
	.arg2name = "newfd",
	.arg2type = ARG_FD,
	.rettype = RET_FD,
	.flags = NEED_ALARM,
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
	.arg1name = "oldfd",
	.arg1type = ARG_FD,
	.arg2name = "newfd",
	.arg2type = ARG_FD,
	.arg3name = "flags",
	.arg3type = ARG_LIST,
	.arg3list = ARGLIST(dup3_flags),
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};
