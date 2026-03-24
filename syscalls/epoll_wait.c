/*
 * SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events, int, maxevents, int, timeout)
 *
 * When  successful, returns the number of file descriptors ready for the requested I/O,
 * or zero if no file descriptor became ready during the requested timeout milliseconds.
 * When an error occurs, returns -1 and errno is set appropriately.
 */
#include "sanitise.h"

struct syscallentry syscall_epoll_wait = {
	.name = "epoll_wait",
	.num_args = 4,
	.arg1name = "epfd",
	.arg1type = ARG_FD_EPOLL,
	.arg2name = "events",
	.arg2type = ARG_NON_NULL_ADDRESS,
	.arg3name = "maxevents",
	.arg3type = ARG_RANGE,
	.low3range = 1,
	.hi3range = 128,
	.arg4name = "timeout",
	.arg4type = ARG_RANGE,
	.low4range = -1,
	.hi4range = 5000,
	.rettype = RET_BORING,
	.flags = NEED_ALARM,
	.group = GROUP_VFS,
};
