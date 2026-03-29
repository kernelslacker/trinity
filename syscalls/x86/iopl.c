/*
   long sys_iopl(unsigned int level, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_iopl = {
	.name = "iopl",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "level", [1] = "regs" },
	.low1range = 0, .hi1range = 3,
	.flags = NEEDS_ROOT,
};
