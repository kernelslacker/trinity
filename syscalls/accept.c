/*
 * SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr, int __user *, upeer_addrlen)
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
	.arg3type = ARG_ADDRESS,
};
