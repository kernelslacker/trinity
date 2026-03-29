/*
  sys_getunwind (void __user *buf, size_t buf_size)
 */
#include "sanitise.h"

struct syscallentry syscall_getunwind = {
	.name = "getunwind",
	.num_args = 2,
	.flags = AVOID_SYSCALL, // IA-64 only
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "buf", [1] = "buf_size" },
};
