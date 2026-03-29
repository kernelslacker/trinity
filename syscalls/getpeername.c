/*
 * SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include "net.h"
#include "sanitise.h"

static void sanitise_getpeername(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_getpeername = {
	.name = "getpeername",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "usockaddr", [2] = "usockaddr_len" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_getpeername,
};
