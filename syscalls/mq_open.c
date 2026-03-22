/*
 * SYSCALL_DEFINE4(mq_open, const char __user *, u_name, int, oflag, mode_t, mode, struct mq_attr __user *, u_attr)
 */
#include <fcntl.h>
#include "sanitise.h"

static unsigned long mq_open_flags[] = {
	O_RDONLY, O_WRONLY, O_RDWR,
	O_CREAT, O_EXCL, O_NONBLOCK,
};

struct syscallentry syscall_mq_open = {
	.name = "mq_open",
	.group = GROUP_IPC,
	.num_args = 4,
	.arg1name = "u_name",
	.arg1type = ARG_ADDRESS,
	.arg2name = "oflag",
	.arg2type = ARG_LIST,
	.arg2list = ARGLIST(mq_open_flags),
	.arg3name = "mode",
	.arg3type = ARG_MODE_T,
	.arg4name = "u_attr",
	.arg4type = ARG_ADDRESS,
	.rettype = RET_FD,
};
