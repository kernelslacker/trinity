/*
 * SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
                 struct getcpu_cache __user *, unused)
 */
#include "sanitise.h"

struct syscallentry syscall_getcpu = {
	.name = "getcpu",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS },
	.argname = { [0] = "cpup", [1] = "nodep", [2] = "unused" },
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
};
