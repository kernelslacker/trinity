/*
 * SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
	unsigned, flags, struct sockaddr __user *, addr,
	int __user *, addr_len)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_recvfrom = {
	.name = "recvfrom",
	.num_args = 6,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "ubuf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "size",
	.arg3type = ARG_LEN,
	.arg5name = "addr",
	.arg5type = ARG_ADDRESS2,
	.arg6name = "addr_len",
	.arg6type = ARG_ADDRESS2,
};
