/*
   long sys_iopl(unsigned int level, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_iopl = {
	.name = "iopl",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "level", [1] = "regs" },
	.arg_params[0].range.low = 0, .arg_params[0].range.hi = 3,
	.flags = NEEDS_ROOT,
};
