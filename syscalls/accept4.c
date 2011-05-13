/*
 * SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
	 int __user *, upeer_addrlen, int, flags)
 */

#define SOCK_CLOEXEC 02000000
#define SOCK_NONBLOCK 04000

#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_accept4 = {
	.name = "accept4",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "upeer_sockaddr",
	.arg2type = ARG_ADDRESS,
	.arg3name = "upeer_addrlen",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = {
		.num = 2,
		.values = { SOCK_NONBLOCK, SOCK_CLOEXEC },
	},
};
