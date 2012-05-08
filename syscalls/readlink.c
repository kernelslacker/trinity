/*
 * SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf, int, bufsiz)
 */
#include "trinity.h"
#include "sanitise.h"

struct syscall syscall_readlink = {
	.name = "readlink",
	.num_args = 3,
	.arg1name = "path",
	.arg1type = ARG_PATHNAME,
	.arg2name = "buf",
	.arg2type = ARG_ADDRESS,
	.arg3name = "bufsiz",
	.arg3type = ARG_LEN,
};
