/*
 * unsigned long sys_sigreturn(struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_sigreturn = {
	.name = "rt_sigreturn",
	.group = GROUP_SIGNAL,
	.num_args = 1,
	.flags = AVOID_SYSCALL, // Confuses the signal state and causes the fuzzer to hang with timeout not firing
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "regs" },
};
