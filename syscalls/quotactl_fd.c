/*
 * SYSCALL_DEFINE4(quotactl_fd, unsigned int, fd, unsigned int, cmd,
	 qid_t, id, void __user *, addr)
 */
#include "sanitise.h"

struct syscallentry syscall_quotactl_fd = {
	.name = "quotactl_fd",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg3name = "id",
	.arg4name = "addr",
	.arg4type = ARG_ADDRESS,
	.group = GROUP_VFS,
};
