/*
   long sys_iopl(unsigned int level, struct pt_regs *regs)
 */
#include "sanitise.h"

struct syscallentry syscall_iopl = {
	.name = "iopl",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "level" },
	.arg_params[0].range.low = 0, .arg_params[0].range.hi = 3,
	.flags = NEEDS_ROOT,
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
