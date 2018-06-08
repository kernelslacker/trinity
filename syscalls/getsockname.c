/*
 * SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include "net.h"
#include "sanitise.h"

static void sanitise_getsockname(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_getsockname = {
	.name = "getsockname",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "usockaddr",
	.arg2type = ARG_SOCKADDR,
	.arg3name = "usockaddr_len",
	.arg3type = ARG_SOCKADDRLEN,
	.flags = NEED_ALARM,
	.sanitise = sanitise_getsockname,
};
