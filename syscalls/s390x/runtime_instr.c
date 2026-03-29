/*
 * int runtime_instr(int on_off, int sig_nr)
 */

#include "sanitise.h"

#define S390_RUNTIME_INSTR_START	0x1
#define S390_RUNTIME_INSTR_STOP		0x2

static unsigned long syscall_runtime_instr_arg1[] = {
	0, S390_RUNTIME_INSTR_START, S390_RUNTIME_INSTR_STOP, 3
};

struct syscallentry syscall_runtime_instr = {
	.name = "runtime_instr",
	.num_args = 2,
	.argtype = { [0] = ARG_LIST, [1] = ARG_RANGE },
	.argname = { [0] = "on_off", [1] = "sig_nr" },
	.arg_params[0].list = ARGLIST(syscall_runtime_instr_arg1),
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 128,
	.rettype = RET_ZERO_SUCCESS
};
