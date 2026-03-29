/*
 * int sys_vm86old(struct vm86_struct __user *v86, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_vm86old = {
	.name = "vm86old",
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS },
	.argname = { [0] = "v86", [1] = "regs" },
};
