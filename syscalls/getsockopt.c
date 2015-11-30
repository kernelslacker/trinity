/*
 * SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname, char __user *, optval, int __user *, optlen)
 */
#include "net.h"
#include "sanitise.h"

static void sanitise_getsockopt(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_getsockopt = {
	.name = "getsockopt",
	.num_args = 5,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "level",
	.arg3name = "optname",
	.arg4name = "optval",
	.arg4type = ARG_ADDRESS,
	.arg5name = "optlen",
	.arg5type = ARG_LEN,
	.flags = NEED_ALARM,
	.sanitise = sanitise_getsockopt,
};
