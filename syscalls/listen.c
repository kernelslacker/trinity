/*
 * SYSCALL_DEFINE2(listen, int, fd, int, backlog)
 */
#include "sanitise.h"

struct syscallentry syscall_listen = {
	.name = "listen",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_SOCKET, [1] = ARG_RANGE },
	.argname = { [0] = "fd", [1] = "backlog" },
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 128,
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
};
