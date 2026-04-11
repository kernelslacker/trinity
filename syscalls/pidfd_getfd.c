/*
 * SYSCALL_DEFINE3(pidfd_getfd, int, pidfd, int, fd, unsigned int, flags)
 */
#include <unistd.h>
#include "sanitise.h"

static unsigned long pidfd_getfd_flags[] = {
	0,
};

static void post_pidfd_getfd(struct syscallrecord *rec)
{
	int fd = rec->retval;

	if (fd != -1)
		close(fd);
}

struct syscallentry syscall_pidfd_getfd = {
	.name = "pidfd_getfd",
	.group = GROUP_PROCESS,
	.num_args = 3,
	.argtype = { [0] = ARG_FD_PIDFD, [1] = ARG_FD, [2] = ARG_LIST },
	.argname = { [0] = "pidfd", [1] = "fd", [2] = "flags" },
	.arg_params[2].list = ARGLIST(pidfd_getfd_flags),
	.rettype = RET_FD,
	.post = post_pidfd_getfd,
};
