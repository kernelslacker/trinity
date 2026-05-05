/*
 * SYSCALL_DEFINE2(shutdown, int, fd, int, how)
 */
#include <sys/socket.h>
#include "sanitise.h"

static unsigned long shutdown_hows[] = {
	SHUT_RD, SHUT_WR, SHUT_RDWR,
};

struct syscallentry syscall_shutdown = {
	.name = "shutdown",
	.num_args = 2,
	.argtype = { [0] = ARG_FD_SOCKET, [1] = ARG_OP },
	.argname = { [0] = "fd", [1] = "how" },
	.arg_params[1].list = ARGLIST(shutdown_hows),
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
};
