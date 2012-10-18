/*
 * SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname,
	 int, newdfd, const char __user *, newname, int, flags)
 */
#include <fcntl.h>

#include "trinity.h"
#include "sanitise.h"
#include "compat.h"

struct syscall syscall_linkat = {
	.name = "linkat",
	.num_args = 5,
	.arg1name = "olddfd",
	.arg1type = ARG_FD,
	.arg2name = "oldname",
	.arg2type = ARG_ADDRESS,
	.arg3name = "newdfd",
	.arg3type = ARG_FD,
	.arg4name = "newname",
	.arg4type = ARG_ADDRESS,
	.arg5name = "flags",
	.arg5type = ARG_LIST,
	.arg5list = {
		.num = 2,
		.values = { AT_SYMLINK_FOLLOW , AT_EMPTY_PATH },
	},
	.flags = NEED_ALARM,
};
