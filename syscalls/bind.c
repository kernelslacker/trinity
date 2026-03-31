/*
 * SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <sys/socket.h>
#include "net.h"
#include "sanitise.h"

static void sanitise_bind(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_bind = {
	.name = "bind",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "umyaddr", [2] = "addrlen" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_bind,
};
