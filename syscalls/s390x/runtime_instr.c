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
	.arg1name = "on_off",
	.arg1type = ARG_LIST,
	.arg1list = ARGLIST(syscall_runtime_instr_arg1),
	.arg2name = "sig_nr",
	.arg2type = ARG_RANGE,
	.low2range = 0,
	.hi2range = 128,
	.rettype = RET_ZERO_SUCCESS
};
