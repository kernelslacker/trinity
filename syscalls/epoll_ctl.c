/*
 * SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event __user *, event)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_epoll_ctl = {
	.name = "epoll_ctl",
	.num_args = 4,
	.arg1name = "epfd",
	.arg1type = ARG_FD,
	.arg2name = "op",
	.arg3name = "fd",
	.arg3type = ARG_FD,
	.arg4name = "event",
	.arg4type = ARG_ADDRESS,
};
