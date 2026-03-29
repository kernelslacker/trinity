/*
 * SYSCALL_DEFINE1(brk, unsigned long, brk)
 *
 * On success: Returns the new program break
 * On failure: Returns current program break
 */
#include "sanitise.h"

struct syscallentry syscall_brk = {
	.name = "brk",
	.num_args = 1,
	.argtype = { [0] = ARG_ADDRESS },
	.argname = { [0] = "brk" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,
	.group = GROUP_VM,
};
