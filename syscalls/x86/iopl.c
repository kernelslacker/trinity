/*
   long sys_iopl(unsigned int level, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_iopl = {
	.name = "iopl",
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "level", [1] = "regs" },
	.flags = NEEDS_ROOT,
};
