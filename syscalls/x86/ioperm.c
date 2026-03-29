/*
   asmlinkage long sys_ioperm(unsigned long from, unsigned long num, int turn_on)
 */
#include "sanitise.h"

struct syscallentry syscall_ioperm = {
	.name = "ioperm",
	.num_args = 3,
	.argname = { [0] = "from", [1] = "num", [2] = "turn_on" },
	.flags = AVOID_SYSCALL | NEEDS_ROOT,
};
