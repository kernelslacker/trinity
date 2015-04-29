/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "net.h"
#include "sanitise.h"

static void sanitise_accept(struct syscallrecord *rec)
{
	rec->a1 = generic_fd_from_socketinfo((struct socketinfo *) rec->a1);
}

struct syscallentry syscall_accept = {
	.name = "accept",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_SOCKETINFO,
	.arg2name = "upeer_sockaddr",
	.arg2type = ARG_SOCKADDR,
	.arg3name = "upeer_addrlen",
	.arg3type = ARG_SOCKADDRLEN,
	.rettype = RET_FD,
	.flags = NEED_ALARM,
	.sanitise = sanitise_accept,
};


/*
 * SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
	 int __user *, upeer_addrlen, int, flags)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 *
 */

struct syscallentry syscall_accept4 = {
	.name = "accept4",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "upeer_sockaddr",
	.arg2type = ARG_SOCKADDR,
	.arg3name = "upeer_addrlen",
	.arg3type = ARG_SOCKADDRLEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 2,
		.values = { SOCK_NONBLOCK, SOCK_CLOEXEC },
	},
	.rettype = RET_FD,
	.flags = NEED_ALARM,
};
