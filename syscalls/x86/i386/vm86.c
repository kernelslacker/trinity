/*
 * int sys_vm86(unsigned long cmd, unsigned long arg, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_vm86 = {
	.name = "vm86",
	.num_args = 3,
	.argtype = { [2] = ARG_ADDRESS },
	.argname = { [0] = "cmd", [1] = "arg", [2] = "regs" },
};
