/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
 *
 * On success, these system calls return a nonnegative integer that is a descriptor for the accepted socket.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_accept = {
	.name = "accept",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "upeer_sockaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "upeer_addrlen",
	.arg3type = ARG_ADDRESS2,
	.rettype = RET_FD,
};
