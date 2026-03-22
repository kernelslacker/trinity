/*
 * SYSCALL_DEFINE2(listen, int, fd, int, backlog)
 */
#include "sanitise.h"

struct syscallentry syscall_listen = {
	.name = "listen",
	.num_args = 2,
	.arg1name = "fd",
	.arg1type = ARG_FD_SOCKET,
	.arg2name = "backlog",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 128,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
};
