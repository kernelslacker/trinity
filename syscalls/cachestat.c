/*
 * SYSCALL_DEFINE4(cachestat, unsigned int, fd,
 *		struct cachestat_range __user *, cstat_range,
 *		struct cachestat __user *, cstat, unsigned int, flags)
 */
#include "sanitise.h"

struct syscallentry syscall_cachestat = {
	.name = "cachestat",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cstat_range",
	.arg2type = ARG_ADDRESS,
	.arg3name = "cstat",
	.arg3type = ARG_ADDRESS,
	.arg4name = "flags",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_VFS,
};
