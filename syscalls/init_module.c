/*
 * SYSCALL_DEFINE3(init_module, void __user *, umod,
	 unsigned long, len, const char __user *, uargs)
 */
#include "sanitise.h"

struct syscallentry syscall_init_module = {
	.name = "init_module",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "umod", [1] = "len", [2] = "uargs" },
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
};
