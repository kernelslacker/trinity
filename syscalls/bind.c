/*
 * SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_bind = {
	.name = "bind",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "umyaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "addrlen",
	.arg3type = ARG_LEN,
};
