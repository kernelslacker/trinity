/*
 * SYSCALL_DEFINE1(mq_unlink, const char __user *, u_name)
 */
#include "sanitise.h"

struct syscallentry syscall_mq_unlink = {
	.name = "mq_unlink",
	.group = GROUP_IPC,
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "u_name" },
};
