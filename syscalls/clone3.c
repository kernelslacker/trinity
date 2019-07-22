/*
 * SYSCALL_DEFINE2(clone3, struct clone_args __user *, uargs, size_t, size)
 */

#include <linux/sched.h>
#include "sanitise.h"

struct syscallentry syscall_clone3 = {
	.name = "clone3",
	.num_args = 2,
	.flags = AVOID_SYSCALL,
	.arg1name = "uargs",
	.arg1type = ARG_ADDRESS,
	.arg2name = "size",
	.arg2type = ARG_LEN,
	.rettype = RET_PID_T,
};
